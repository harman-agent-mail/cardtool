import io, json, sys, tempfile, types, unittest
from contextlib import redirect_stdout
from pathlib import Path
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
