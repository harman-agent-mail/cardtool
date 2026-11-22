import io, json, sys, tempfile, types, unittest, urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cardtool

class TestValidate(unittest.TestCase):
    def test_my_card_is_valid(self):
        ok, errors, _ = cardtool.validate(cardtool.my_card())
        self.assertTrue(ok, f"my own card must validate, got: {errors}")

    def test_missing_required_field_fails(self):
        c = cardtool.my_card(); del c["skills"]
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok); self.assertTrue(any("skills" in e for e in errors))

    def test_empty_skill_field_fails(self):
        c = cardtool.my_card(); c["skills"][0]["description"] = ""
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok)

    def test_duplicate_skill_id_fails(self):
        c = cardtool.my_card(); c["skills"][1]["id"] = c["skills"][0]["id"]
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok); self.assertTrue(any("duplicate" in e for e in errors))

    def test_secret_leak_fails(self):
        c = cardtool.my_card(); c["description"] += " api_key: hunter2supersecret"
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok); self.assertTrue(any("secret" in e for e in errors))

    def test_non_https_url_fails(self):
        c = cardtool.my_card(); c["url"] = "http://example.com/card.json"
        ok, errors, _ = cardtool.validate(c)
        self.assertFalse(ok)

    def test_no_fake_payments_claim(self):
        # lab honesty rule: jarvis does not take payments; card must say so
        self.assertFalse(cardtool.my_card()["x402Support"])
        self.assertFalse(cardtool.my_card()["erc8004"]["active"])

def _run(fn, **kw):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = fn(types.SimpleNamespace(**kw))
    return rc, buf.getvalue()

class TestAccountability(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.log = str(Path(self._tmp.name) / "actions.jsonl")
        rc, _ = _run(cardtool.cmd_acct_init, log=self.log)
        self.assertEqual(rc, 0)

    def tearDown(self):
        self._tmp.cleanup()

    def _add(self, action, detail):
        rc, _ = _run(cardtool.cmd_acct_add, log=self.log, action=action, detail=detail)
        self.assertEqual(rc, 0)

    def _lines(self):
        return Path(self.log).read_text(encoding="utf-8").splitlines()

    def _write_lines(self, lines):
        Path(self.log).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_chain_verifies_after_several_adds(self):
        self._add("deploy", "shipped v1")
        self._add("audit", "ran signpost check")
        self._add("publish", "posted digest")
        rc, out = _run(cardtool.cmd_acct_verify, log=self.log, head=None)
        self.assertEqual(rc, 0, out)
        self.assertIn("INTACT", out)
        self.assertIn("4 entries", out)  # genesis + 3 adds

    def test_init_refuses_to_overwrite(self):
        rc, _ = _run(cardtool.cmd_acct_init, log=self.log)
        self.assertNotEqual(rc, 0)

    def test_tampered_middle_detail_detected_at_that_entry(self):
        self._add("a1", "d1"); self._add("a2", "d2"); self._add("a3", "d3")
        lines = self._lines()
        e = json.loads(lines[2]); e["detail"] = "forged after the fact"
        lines[2] = json.dumps(e, sort_keys=True)
        self._write_lines(lines)
        rc, out = _run(cardtool.cmd_acct_verify, log=self.log, head=None)
        self.assertNotEqual(rc, 0)
        self.assertIn("entry 2", out)
        self.assertIn("hash mismatch", out)

    def test_deleted_entry_detected(self):
        self._add("a1", "d1"); self._add("a2", "d2"); self._add("a3", "d3")
        lines = self._lines()
        del lines[2]  # remove the seq-2 entry entirely
        self._write_lines(lines)
        rc, out = _run(cardtool.cmd_acct_verify, log=self.log, head=None)
        self.assertNotEqual(rc, 0)
        self.assertIn("sequence mismatch", out)

    def test_truncation_detected_with_recorded_head(self):
        self._add("a1", "d1"); self._add("a2", "d2"); self._add("a3", "d3")
        rc, out = _run(cardtool.cmd_acct_export, log=self.log)
        self.assertEqual(rc, 0)
        head = json.loads(out)["head"]
        self._write_lines(self._lines()[:-1])  # silently drop the last entry
        # a shortened chain is still internally valid (documented limitation)…
        rc_plain, _ = _run(cardtool.cmd_acct_verify, log=self.log, head=None)
        self.assertEqual(rc_plain, 0)
        # …but against the externally recorded head, truncation is caught
        rc_head, out_head = _run(cardtool.cmd_acct_verify, log=self.log, head=head)
        self.assertNotEqual(rc_head, 0)
        self.assertIn("head mismatch", out_head)

    def test_export_output_shape(self):
        self._add("deploy", "shipped v1")
        rc, out = _run(cardtool.cmd_acct_export, log=self.log)
        self.assertEqual(rc, 0)
        s = json.loads(out)
        self.assertEqual(s["format"], "cardtool-accountability/1")
        self.assertEqual(s["entries"], 2)  # genesis + 1 add
        self.assertRegex(s["head"], r"^[0-9a-f]{64}$")
        self.assertIn("first_ts", s); self.assertIn("last_ts", s)
        self.assertLessEqual(s["first_ts"], s["last_ts"])

    def test_add_refuses_to_extend_broken_chain(self):
        self._add("a1", "d1")
        lines = self._lines()
        e = json.loads(lines[1]); e["detail"] = "forged"
        lines[1] = json.dumps(e, sort_keys=True)
        self._write_lines(lines)
        rc, out = _run(cardtool.cmd_acct_add, log=self.log, action="a2", detail="d2")
        self.assertNotEqual(rc, 0)
        self.assertIn("broken", out)

class _FakeResp:
    """Minimal urlopen response: context manager with .status and .read()."""
    def __init__(self, status, body):
        self.status = status; self._body = body
    def read(self): return self._body
    def __enter__(self): return self
    def __exit__(self, *a): return False

def _http_error(url, code):
    return urllib.error.HTTPError(url, code, f"HTTP {code}", {}, None)

def _valid_card_bytes():
    return json.dumps(cardtool.my_card()).encode()

class TestCheckUrl(unittest.TestCase):
    URL = "https://example.com/.well-known/agent-card.json"

    def _check(self, side_effect):
        with mock.patch("cardtool.urllib.request.urlopen") as m:
            m.side_effect = side_effect
            rc, out = _run(cardtool.cmd_check_url, url="https://example.com")
            return rc, out, m

    def _ua_of(self, mocked, call_index):
        req = mocked.call_args_list[call_index][0][0]
        return req.get_header("User-agent")

    def test_plain_valid_unchanged(self):
        rc, out, m = self._check([_FakeResp(200, _valid_card_bytes())])
        self.assertEqual(rc, 0, out)
        self.assertIn("SIGNPOST VALID (HTTP 200)", out)
        self.assertEqual(m.call_count, 1)  # no retry on a plain success

    def test_plain_404_missing_unchanged(self):
        rc, out, m = self._check([_http_error(self.URL, 404)])
        self.assertEqual(rc, 1, out)
        self.assertIn("SIGNPOST MISSING/UNREACHABLE", out)
        self.assertEqual(m.call_count, 1)  # no retry for non-401/403

    def test_plain_500_no_retry(self):
        rc, out, m = self._check([_http_error(self.URL, 500)])
        self.assertEqual(rc, 1, out)
        self.assertIn("SIGNPOST MISSING/UNREACHABLE", out)
        self.assertEqual(m.call_count, 1)

    def test_gated_403_retry_returns_valid_card(self):
        rc, out, m = self._check([_http_error(self.URL, 403),
                                  _FakeResp(200, _valid_card_bytes())])
        self.assertEqual(m.call_count, 2)
        self.assertIsNone(self._ua_of(m, 0))  # first fetch: plain client
        self.assertIn("Mozilla/5.0", self._ua_of(m, 1))  # retry: browser UA
        self.assertIn("SIGNPOST GATED (valid card, refuses plain clients)", out)
        self.assertNotIn("SIGNPOST VALID", out)
        self.assertNotIn("MISSING", out)
        self.assertEqual(rc, 1, out)  # gated is not walkable by a plain client

    def test_gated_401_retry_returns_valid_card(self):
        rc, out, m = self._check([_http_error(self.URL, 401),
                                  _FakeResp(200, _valid_card_bytes())])
        self.assertEqual(m.call_count, 2)
        self.assertIn("SIGNPOST GATED (valid card, refuses plain clients)", out)
        self.assertEqual(rc, 1, out)

    def test_gated_retry_still_refused_is_missing(self):
        rc, out, m = self._check([_http_error(self.URL, 403),
                                  _http_error(self.URL, 403)])
        self.assertEqual(m.call_count, 2)
        self.assertIn("SIGNPOST MISSING/UNREACHABLE", out)
        self.assertNotIn("GATED", out)
        self.assertEqual(rc, 1, out)

    def test_gated_retry_invalid_card(self):
        bad = cardtool.my_card(); del bad["url"]
        rc, out, m = self._check([_http_error(self.URL, 403),
                                  _FakeResp(200, json.dumps(bad).encode())])
        self.assertEqual(m.call_count, 2)
        self.assertIn("SIGNPOST GATED (invalid card, refuses plain clients)", out)
        self.assertIn("missing/empty required field: url", out)
        self.assertEqual(rc, 1, out)

    def test_gated_retry_non_json(self):
        rc, out, m = self._check([_http_error(self.URL, 403),
                                  _FakeResp(200, b"<html>not a card</html>")])
        self.assertEqual(m.call_count, 2)
        self.assertIn("SIGNPOST GATED (non-JSON response, refuses plain clients)", out)
        self.assertEqual(rc, 1, out)

if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestConcordium(unittest.TestCase):
    """Read-only checks against the hosted Agent Registry MCP REST API.
    All network calls are mocked; the live endpoint shape was verified by
    hand on 2026-11-19 against badge Mf22soLh1NuZYFgBK8iSs (badge_valid=true,
    verify-agent-card match=true)."""
    BADGE = "Mf22soLh1NuZYFgBK8iSs"

    def _badge_body(self, valid=True):
        return {
            "token_id": 484, "token_address": self.BADGE, "network": "mainnet",
            "agent_uri": "https://example.com/.well-known/agent-card.json",
            "http_status": 200,
            "card_sha256": "a" * 64,
            "on_chain": {"owner_account": "4DDx", "status": "Active",
                         "agent_uri": "https://example.com/.well-known/agent-card.json",
                         "metadata_hash_hex": "a" * 64},
            "checks": {"on_chain_agent_found": True, "status_active": True,
                       "has_agent_uri": True, "card_fetched": True,
                       "hash_matches_on_chain": valid, "badge_present": True},
            "badge_valid": valid,
            "issues": [] if valid else [{"severity": "error", "field": "hash",
                                         "message": "card hash mismatch"}],
        }

    def _verify_body(self, match=True):
        return {"network": "mainnet", "token_id": "484",
                "on_chain_uri": "https://example.com/.well-known/agent-card.json",
                "on_chain_hash_hex": "a" * 64,
                "fetched": {"http_status": 200, "byte_length": 1234,
                            "sha256_hex": "a" * 64 if match else "b" * 64},
                "match": match}

    def _run_conc(self, fn, body, status=200):
        with mock.patch("cardtool.urllib.request.urlopen") as m:
            m.return_value = _FakeResp(status, json.dumps(body).encode())
            rc, out = _run(fn, badge=self.BADGE, network=None)
            return rc, out, m

    def test_check_badge_valid(self):
        rc, out, m = self._run_conc(cardtool.cmd_conc_check_badge, self._badge_body(True))
        self.assertEqual(rc, 0, out)
        self.assertIn("CONCORDIUM BADGE VALID", out)
        self.assertIn("hash_matches_on_chain", out)
        self.assertEqual(m.call_count, 1)
        url = m.call_args_list[0][0][0].full_url
        self.assertIn("/v1/check-badge/" + self.BADGE, url)

    def test_check_badge_invalid(self):
        rc, out, _ = self._run_conc(cardtool.cmd_conc_check_badge, self._badge_body(False))
        self.assertEqual(rc, 1, out)
        self.assertIn("CONCORDIUM BADGE INVALID", out)
        self.assertIn("checks FAILED: hash_matches_on_chain", out)

    def test_check_badge_bad_id_is_failure_not_crash(self):
        with mock.patch("cardtool.urllib.request.urlopen") as m:
            m.side_effect = [_http_error("x", 400)]
            rc, out = _run(cardtool.cmd_conc_check_badge, badge="not-a-badge", network=None)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAILED (HTTP 400)", out)

    def test_verify_card_match(self):
        rc, out, _ = self._run_conc(cardtool.cmd_conc_verify_card, self._verify_body(True))
        self.assertEqual(rc, 0, out)
        self.assertIn("MATCHES", out)

    def test_verify_card_mismatch(self):
        rc, out, _ = self._run_conc(cardtool.cmd_conc_verify_card, self._verify_body(False))
        self.assertEqual(rc, 1, out)
        self.assertIn("DOES NOT MATCH", out)

    def test_badge_json_prints_extension(self):
        body = {"network": "mainnet", "token_address": self.BADGE, "token_id": 484,
                "status": "Active",
                "extension": {"uri": "https://docs.concordium.com/a2a-extensions/concordium-badge/v1",
                              "params": {"tokenAddress": "ccd:9dd9:cis-2:" + self.BADGE}},
                "registrations_entry": {"agentId": 484}}
        rc, out, _ = self._run_conc(cardtool.cmd_conc_badge_json, body)
        self.assertEqual(rc, 0, out)
        self.assertIn(self.BADGE, out)
        self.assertIn("concordium-badge/v1", out)

    # --- contract-info ---
    _CONFIG_JS = ('window.AGENT_REGISTRY_UI_CONFIG = { networks: {'
                  ' testnet: { agentRegistry: { contractName: "CIS-8004", contractIndex: "12802", contractSubindex: "0" },'
                  ' cisx: { contractName: "CIS-8", contractIndex: "12801", contractSubindex: "0" } },'
                  ' mainnet: { agentRegistry: { contractName: "CIS-8004", contractIndex: "10082", contractSubindex: "0" },'
                  ' cisx: { contractName: "CIS-8", contractIndex: "10081", contractSubindex: "0" } } } };')

    def _check_badge_body(self, cis8004="12802,0", cis8="12801,0"):
        body = self._badge_body(True)
        body["token_id"] = 0
        body["token_address"] = "JyP9TtQC3HCNrTYR3sc2T"
        body["network"] = "testnet"
        body["expected"] = {"contracts": {"cis8004": cis8004, "cis8": cis8}}
        return body

    def _run_contract_info(self, config_text, badge_body=None, status=200):
        responses = [_FakeResp(200, config_text.encode())]
        if badge_body is not None:
            responses.append(_FakeResp(status, json.dumps(badge_body).encode()))
        with mock.patch("cardtool.urllib.request.urlopen") as m:
            m.side_effect = responses
            rc, out = _run(cardtool.cmd_conc_contract_info, network="testnet")
            return rc, out, m

    def test_token_badge_reproduces_known_badges(self):
        # Mainnet badges verified live 2026-11-19 (token 484) and from
        # gregers.dev (token 40); testnet token 0 verified live 2026-11-20
        # against the indexer record + the MCP expected.contracts field.
        self.assertEqual(cardtool.concordium_token_badge(10082, 0, 484), "Mf22soLh1NuZYFgBK8iSs")
        self.assertEqual(cardtool.concordium_token_badge(10082, 0, 40), "Mf22pFZuWLFzMWDPP4qzj")
        self.assertEqual(cardtool.concordium_token_badge(12802, 0, 0), "JyP9TtQC3HCNrTYR3sc2T")

    def test_contract_info_testnet_confirmed(self):
        rc, out, m = self._run_contract_info(self._CONFIG_JS, self._check_badge_body())
        self.assertEqual(rc, 0, out)
        self.assertIn("CIS-8004 12802,0", out)
        self.assertIn("CIS-8 12801,0", out)
        self.assertIn("CONFIRMED", out)
        self.assertEqual(m.call_count, 2)
        self.assertIn("config.js", m.call_args_list[0][0][0].full_url)
        self.assertIn("JyP9TtQC3HCNrTYR3sc2T", m.call_args_list[1][0][0].full_url)

    def test_contract_info_mismatch_fails(self):
        rc, out, _ = self._run_contract_info(self._CONFIG_JS, self._check_badge_body("99999,0", "12801,0"))
        self.assertEqual(rc, 1, out)
        self.assertIn("MISMATCH", out)

    def test_contract_info_bad_config_fails(self):
        rc, out, _ = self._run_contract_info("window.AGENT_REGISTRY_UI_CONFIG = {};")
        self.assertEqual(rc, 1, out)
        self.assertIn("FAILED", out)

    def test_my_card_version_and_head_anchor(self):
        c = cardtool.my_card()
        self.assertEqual(c["version"], "0.3.4")
        acct = c["accountability"]
        self.assertEqual(acct["entries"], 15)
        self.assertEqual(acct["head"], "adc271f4e6b4e33eebfe221e9ded152c94dcf9a0c1e75324b7227ebfc289b91c")
        self.assertEqual(acct["anchored"], "2026-11-22")

    def test_generate_reproduces_published_card(self):
        with tempfile.TemporaryDirectory() as d:
            out = str(Path(d) / "agent-card.json")
            rc, _ = _run(cardtool.cmd_generate, out=out)
            self.assertEqual(rc, 0)
            published = Path(__file__).resolve().parents[1] / "output" / "agent-card.json"
            self.assertEqual(Path(out).read_bytes(), published.read_bytes(),
                             "generate must reproduce the published card byte-for-byte")
