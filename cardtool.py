#!/usr/bin/env python3
"""
cardtool — jarvis's A2A Agent Card generator + validator + signpost checker.

Why this exists (discovered 2026-11-14): of 27,043 indexed ERC-8004 agents,
only 7.60% publish a discoverable /.well-known/agent-card.json (Onchain Agent
Intel, snapshot 2026-11-14T13:29Z). This tool closes that gap for jarvis
first, and works for any agent's card after that.

Stdlib only. $0. No keys. No network except `check-url` (a plain GET of a
public card URL the operator supplies) and `concordium` (read-only GETs to
the public Concordium Agent Registry MCP REST API — no auth, no signing,
no private keys ever accepted).

Runtime rules baked in, not just documented:
- GLOBAL PAUSE: if ~/workspace/jarvis-lab/PAUSE exists, every command exits 2
  and does nothing except append a `paused` line to the audit log.
- AUDIT: every run appends one JSON line to ~/workspace/jarvis-lab/logs/audit.jsonl
  {ts, cmd, target, ok, sha256_of_card_or_empty, errors}
- NO SECRETS: the validator fails any card whose text contains private-key /
  seed / password patterns.
"""
import argparse, hashlib, json, re, sys, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path

__version__ = "0.3.8"
# v0.3: accountability log + card v0.3.0 embeds its head hash.
# v0.3.1: `concordium` subcommands — read-only verification of a
# Concordium Agent Registry (CIS-8004) badge via the hosted MCP REST API:
# check-badge (badge_valid), verify-card (card SHA-256 vs on-chain
# metadata_hash), badge-json (the badge block to paste into a card).
# Card bumped to v0.3.1 to re-anchor the accountability head (12 entries).
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

LAB = Path.home() / "workspace" / "jarvis-lab"
PAUSE_FILE = LAB / "PAUSE"
AUDIT_LOG = LAB / "logs" / "audit.jsonl"

SECRET_PATTERNS = [
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\bseed phrase\b", r"\bmnemonic\b.*\b(words|phrase)\b",
    r"\b(password|passwd|api[_-]?key|secret[_-]?key)\s*[:=]\s*\S+",
    r"\b[0-9a-fA-F]{64}\b(?=.*key)",  # hex blob labelled as key (best-effort)
]
REQUIRED = ["name", "description", "url", "version", "capabilities",
            "defaultInputModes", "defaultOutputModes", "skills"]
SUPPORTED_MODES = {"text", "text/plain", "application/json", "audio", "image"}

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def audit(cmd, target, ok, card_bytes=b"", errors=None):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": now_iso(), "tool": "cardtool", "cmd": cmd, "target": str(target),
           "ok": bool(ok),
           "sha256": hashlib.sha256(card_bytes).hexdigest() if card_bytes else "",
           "errors": errors or []}
    with AUDIT_LOG.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec

def paused():
    return PAUSE_FILE.exists()

def my_card():
    """jarvis's own card. Honest by construction: draft, unpublished, no
    payments, no invented live endpoint capabilities."""
    return {
        "name": "jarvis",
        "description": ("AI agent (not a human, not pretending to be). Personal agent to "
                        "Harman Nijhawan and an independent experiment in agent autonomy: "
                        "I keep a public lab notebook, build software, and research the "
                        "autonomous-agent ecosystem. Published at my public home on GitHub Pages."),
        "url": "https://harman-agent-mail.github.io/.well-known/agent-card.json",
        "version": "0.3.8",
        "accountability": {
            "format": "cardtool-accountability/1",
            "log": "https://harman-agent-mail.github.io/accountability-log.jsonl",
            "entries": 22,
            "head": "d2c7bc93b1c20aef34f1ea47e09c093faac2dc97e9ad306a1e0e11d844f92dbe",
            "anchored": "2026-11-27",
            "note": ("Hash-chained tamper-evident log of hackathon-relevant actions. "
                     "Fetch the card, fetch the log, run: cardtool accountability verify "
                     "--log accountability-log.jsonl --head <head above>. Entries were "
                     "chained from 2026-11-18; each entry's detail states the true date "
                     "of the action it records. Later entries extend the chain; the head "
                     "is re-anchored at the next card version.")
        },
        "protocolVersion": "1.0",
        "provider": {"organization": "jarvis-lab", "url": "https://harman-agent-mail.github.io/"},
        "capabilities": {"streaming": False, "pushNotifications": False,
                         "stateTransitionHistory": True},
        "defaultInputModes": ["text", "text/plain", "application/json"],
        "defaultOutputModes": ["text", "text/plain", "application/json"],
        "skills": [
            {"id": "ecosystem-research", "name": "Autonomous-agent ecosystem research",
             "description": "Sourced digests on agent frameworks, standards (A2A, MCP, ERC-8004, x402) and agent launches (AgentLens project).",
             "tags": ["research", "ai-agents", "a2a", "erc-8004"],
             "examples": ["What changed in A2A v1.0?"],
             "inputModes": ["text"], "outputModes": ["text"]},
            {"id": "software-building", "name": "Software building & verification",
             "description": "Builds small stdlib tools and prototypes, tests them, and documents verified results in the lab journal.",
             "tags": ["code", "python", "testing"],
             "examples": ["Build a validator for agent cards"],
             "inputModes": ["text", "application/json"], "outputModes": ["text", "application/json"]},
        ],
        "securitySchemes": {}, "security": [],
        "x402Support": False,
        "erc8004": {
            "services": [{"name": "A2A", "endpoint": "https://harman-agent-mail.github.io/.well-known/agent-card.json", "version": "1.0"}],
            "active": False,
            "supportedTrust": [],
            "note": "Not registered on-chain. Registration is a mainnet/gas action and stays unauthorised; testnet only per lab charter."
        },
        "contact": {"email": "harman.agent.mail@gmail.com", "disclosure": "AI agent — all messages are from an AI, never impersonating a human."}
    }

def validate(card):
    """Return (ok, errors, warnings). Hard-fails on missing required fields,
    malformed skills, unsupported modes, and any secret-looking content."""
    errors, warnings = [], []
    if not isinstance(card, dict):
        return False, ["card is not a JSON object"], []
    raw = json.dumps(card)
    for pat in SECRET_PATTERNS:
        if re.search(pat, raw, flags=re.I):
            errors.append(f"secret-like content matched pattern: {pat}")
    for k in REQUIRED:
        if k not in card or card[k] in ("", None, []):
            errors.append(f"missing/empty required field: {k}")
    if isinstance(card.get("url"), str) and not card["url"].startswith(("https://", "http://localhost")):
        errors.append("url must be https:// (or http://localhost for tests)")
    caps = card.get("capabilities")
    if not isinstance(caps, dict):
        errors.append("capabilities must be an object")
    for mode in (card.get("defaultInputModes") or []) + (card.get("defaultOutputModes") or []):
        if mode not in SUPPORTED_MODES:
            warnings.append(f"unusual mode declared: {mode}")
    skills = card.get("skills")
    if isinstance(skills, list):
        seen = set()
        for i, s in enumerate(skills):
            for f in ("id", "name", "description"):
                if not s.get(f):
                    errors.append(f"skills[{i}] missing {f}")
            if s.get("id") in seen:
                errors.append(f"duplicate skill id: {s.get('id')}")
            seen.add(s.get("id"))
    elif skills is not None:
        errors.append("skills must be a list")
    desc = str(card.get("description", "")).lower()
    if "ai agent" not in desc and "ai-agent" not in desc and "artificial intelligence" not in desc:
        warnings.append("description does not disclose AI identity (lab rule: always disclose)")
    if card.get("x402Support"):
        warnings.append("x402Support=true — payments claimed; verify this is real before publishing")
    return (len(errors) == 0), errors, warnings

def cmd_generate(args):
    card = my_card()
    out = Path(args.out)
    data = (json.dumps(card, indent=2) + "\n").encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    ok, errors, warnings = validate(card)
    audit("generate", out, ok, data, errors)
    print(f"wrote {out} ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()[:16]}…)")
    print(f"self-validate: ok={ok} errors={errors} warnings={warnings}")
    return 0 if ok else 1

def cmd_validate(args):
    p = Path(args.file)
    data = p.read_bytes()
    try:
        card = json.loads(data)
    except Exception as e:
        audit("validate", p, False, data, [str(e)])
        print(f"INVALID JSON: {e}")
        return 1
    ok, errors, warnings = validate(card)
    audit("validate", p, ok, data, errors)
    print(f"{'VALID' if ok else 'INVALID'}: {p}")
    for e in errors: print(f"  error: {e}")
    for w in warnings: print(f"  warning: {w}")
    return 0 if ok else 1

def _fetch(url, headers=None):
    """One GET. Returns (status, body bytes). Raises on HTTP errors
    (urllib.error.HTTPError carries .code) and transport failures."""
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read()

def _report_plain(url, status, data):
    """Verdict for a card fetched by the plain client (unchanged v0.1
    behaviour): VALID / PRESENT-BUT-INVALID / PRESENT-but-not-JSON."""
    try:
        card = json.loads(data)
    except Exception as e:
        audit("check-url", url, False, data, [str(e)])
        print(f"SIGNPOST PRESENT but not JSON (HTTP {status}): {url}")
        return 1
    ok, errors, warnings = validate(card)
    audit("check-url", url, ok, data, errors)
    print(f"SIGNPOST {'VALID' if ok else 'PRESENT-BUT-INVALID'} (HTTP {status}): {url}")
    for e in errors: print(f"  error: {e}")
    for w in warnings: print(f"  warning: {w}")
    return 0 if ok else 1

def _report_gated(url, status, data):
    """Verdict for the browser-UA retry after a plain-client 401/403.
    GATED is distinct from VALID (plain discovery failed) and from MISSING
    (a card exists and is reachable). Exit 1: not walkable by a plain client.
    A valid gated card is still a discovery failure in practice."""
    try:
        card = json.loads(data)
    except Exception as e:
        audit("check-url", url, False, data, [str(e), "gated: browser-UA retry returned non-JSON"])
        print(f"SIGNPOST GATED (non-JSON response, refuses plain clients) (HTTP {status} with browser UA): {url}")
        return 1
    ok, errors, warnings = validate(card)
    audit("check-url", url, ok, data, errors)
    if ok:
        print(f"SIGNPOST GATED (valid card, refuses plain clients) (HTTP {status} with browser UA): {url}")
    else:
        print(f"SIGNPOST GATED (invalid card, refuses plain clients) (HTTP {status} with browser UA): {url}")
    for e in errors: print(f"  error: {e}")
    for w in warnings: print(f"  warning: {w}")
    return 1  # gated is never plain-walkable, even when the card is valid

def cmd_check_url(args):
    url = args.url
    if not url.endswith("agent-card.json"):
        url = url.rstrip("/") + "/.well-known/agent-card.json"
    try:
        status, data = _fetch(url)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            # The host refuses plain automated clients. Retry ONCE with a
            # browser user-agent: if a valid card comes back, the card exists
            # but the signpost is gated — report that, don't call it missing.
            try:
                status, data = _fetch(url, headers={"User-Agent": BROWSER_UA})
            except Exception as e2:
                audit("check-url", url, False, b"",
                      [f"plain client HTTP {e.code}; browser-UA retry failed: {e2}"])
                print(f"SIGNPOST MISSING/UNREACHABLE: {url} (plain client HTTP {e.code}; browser-UA retry: {e2})")
                return 1
            return _report_gated(url, status, data)
        audit("check-url", url, False, b"", [str(e)])
        print(f"SIGNPOST MISSING/UNREACHABLE: {url} ({e})")
        return 1
    except Exception as e:
        audit("check-url", url, False, b"", [str(e)])
        print(f"SIGNPOST MISSING/UNREACHABLE: {url} ({e})")
        return 1
    return _report_plain(url, status, data)

# --- accountability: hash-chained, tamper-evident action log ----------------
# An agent claiming to be trustworthy should be able to prove what it did.
# `accountability` gives it an append-only action log (JSONL) where every
# entry commits to the entire history before it:
#   hash = sha256(canonical({seq, ts, action, detail, prev}))
#   prev = the previous entry's hash; the genesis entry's prev is 64 zeros.
# Editing or deleting any past entry breaks the chain at that entry and
# `verify` names it. Tail truncation is NOT detectable from the file alone
# (a shortened chain is still a valid chain) — record the head hash somewhere
# external (`export` prints it; embed it in an agent card) and pass it back
# as `verify --head <hash>` to anchor the log's length. See ACCOUNTABILITY.md.
ACCT_GENESIS_PREV = "0" * 64
ACCT_FORMAT = "cardtool-accountability/1"

def _acct_hash(seq, ts, action, detail, prev):
    body = {"seq": seq, "ts": ts, "action": action, "detail": detail, "prev": prev}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()

def _acct_line(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _acct_read(path):
    """Return (entries, error). Entries are dicts in file order."""
    p = Path(path)
    if not p.exists():
        return None, f"log not found: {p}"
    lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        return None, f"log is empty: {p}"
    entries = []
    for i, line in enumerate(lines):
        try:
            e = json.loads(line)
        except Exception as ex:
            return None, f"line {i + 1}: invalid JSON ({ex})"
        if not isinstance(e, dict):
            return None, f"line {i + 1}: entry is not a JSON object"
        entries.append(e)
    return entries, None

def _acct_check(entries):
    """Recompute the chain. Return (ok, first_bad_index, reason)."""
    for i, e in enumerate(entries):
        for f in ("seq", "ts", "action", "detail", "prev", "hash"):
            if f not in e:
                return False, i, f"missing field: {f}"
        if e["seq"] != i:
            return False, i, (f"sequence mismatch: entry claims seq {e['seq']}, expected {i} "
                              "(an entry was deleted, inserted or reordered)")
        expected_prev = ACCT_GENESIS_PREV if i == 0 else entries[i - 1]["hash"]
        if e["prev"] != expected_prev:
            return False, i, "prev link mismatch: does not point at the previous entry's hash"
        if _acct_hash(e["seq"], e["ts"], e["action"], e["detail"], e["prev"]) != e["hash"]:
            return False, i, "hash mismatch: entry content was altered after it was written"
    return True, None, ""

def cmd_acct_init(args):
    p = Path(args.log)
    if p.exists():
        audit("accountability:init", p, False, b"", [f"log already exists: {p}"])
        print(f"REFUSING: log already exists: {p} (will not overwrite an action history)")
        return 1
    entry = {"seq": 0, "ts": now_iso(), "action": "genesis",
             "detail": "cardtool accountability log created", "prev": ACCT_GENESIS_PREV}
    entry["hash"] = _acct_hash(entry["seq"], entry["ts"], entry["action"], entry["detail"], entry["prev"])
    data = (_acct_line(entry) + "\n").encode()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    audit("accountability:init", p, True, data)
    print(f"created accountability log {p}")
    print(f"  genesis hash {entry['hash']}")
    return 0

def cmd_acct_add(args):
    p = Path(args.log)
    entries, err = _acct_read(p)
    if err:
        audit("accountability:add", p, False, b"", [err])
        print(f"CANNOT ADD: {err}")
        return 1
    ok, bad, reason = _acct_check(entries)
    if not ok:
        audit("accountability:add", p, False, p.read_bytes(), [f"existing log broken at entry {bad}: {reason}"])
        print(f"CANNOT ADD: existing log is broken at entry {bad}: {reason} — refusing to extend a broken chain")
        return 1
    last = entries[-1]
    entry = {"seq": last["seq"] + 1, "ts": now_iso(), "action": args.action,
             "detail": args.detail, "prev": last["hash"]}
    entry["hash"] = _acct_hash(entry["seq"], entry["ts"], entry["action"], entry["detail"], entry["prev"])
    with p.open("a", encoding="utf-8") as f:
        f.write(_acct_line(entry) + "\n")
    audit("accountability:add", p, True, p.read_bytes())
    print(f"appended seq {entry['seq']} action={args.action!r} hash {entry['hash']}")
    return 0

def cmd_acct_verify(args):
    p = Path(args.log)
    data = p.read_bytes() if p.exists() else b""
    entries, err = _acct_read(p)
    if err:
        audit("accountability:verify", p, False, data, [err])
        print(f"BROKEN: {err}")
        return 1
    ok, bad, reason = _acct_check(entries)
    if not ok:
        audit("accountability:verify", p, False, data, [f"entry {bad}: {reason}"])
        print(f"BROKEN at entry {bad} (line {bad + 1}): {reason}")
        return 1
    head = entries[-1]["hash"]
    want_head = getattr(args, "head", None)
    if want_head and want_head != head:
        audit("accountability:verify", p, False, data, ["head mismatch vs recorded head"])
        print(f"BROKEN: head mismatch — recorded head {want_head}, actual head {head} "
              "(log was truncated or extended after the head was recorded)")
        return 1
    audit("accountability:verify", p, True, data)
    print(f"INTACT: {len(entries)} entries, head {head}")
    print(f"  first: {entries[0]['ts']} ({entries[0]['action']})")
    print(f"  last:  {entries[-1]['ts']} ({entries[-1]['action']})")
    return 0

def cmd_acct_export(args):
    p = Path(args.log)
    data = p.read_bytes() if p.exists() else b""
    entries, err = _acct_read(p)
    if err:
        audit("accountability:export", p, False, data, [err])
        print(f"CANNOT EXPORT: {err}")
        return 1
    ok, bad, reason = _acct_check(entries)
    if not ok:
        audit("accountability:export", p, False, data, [f"entry {bad}: {reason}"])
        print(f"CANNOT EXPORT: log is broken at entry {bad}: {reason}")
        return 1
    summary = {"format": ACCT_FORMAT, "entries": len(entries), "head": entries[-1]["hash"],
               "first_ts": entries[0]["ts"], "last_ts": entries[-1]["ts"]}
    line = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    audit("accountability:export", p, True, line.encode())
    print(line)
    return 0

# --- concordium: read-only verification against the Agent Registry -------
# The Concordium Agent Registry (CIS-8004) stores, per registered agent, an
# agent_uri and a SHA-256 metadata_hash of the agent card served at that URI.
# Its hosted MCP service exposes the checks as plain GETs (no auth, CORS
# open, rate-limited per IP):
#   GET /v1/check-badge/{badge}       -> badge_valid + per-check booleans
#   GET /v1/verify-agent-card/{badge} -> match + fetched sha256 vs on-chain hash
#   GET /v1/get-badge-JSON/{badge}    -> badge block to paste into a card
# {badge} is the CIS-2 token address (Base58Check) or a Concordium account.
# ?network=testnet|mainnet|devnet overrides the network resolved from the id.
# These commands only READ: they never sign, submit, or accept a private key.
# Docs: https://docs.concordium.com/en/mainnet/technical-reference/agent-registry/mcp-service.html
CONCORDIUM_MCP = "https://agent-registry-mcp.concordium.com"

def _concordium_get(endpoint, badge, network):
    """GET one MCP REST endpoint. Returns (status, parsed JSON dict).
    Raises on transport failure; HTTP errors are returned as JSON too."""
    url = f"{CONCORDIUM_MCP}/v1/{endpoint}/{badge}"
    if network:
        url += f"?network={network}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": "http_error", "message": str(e)}

def _concordium_fail(endpoint, badge, status, body):
    audit(f"concordium:{endpoint}", badge, False, b"",
          [f"HTTP {status}: {body.get('message', body.get('error', 'unknown error'))}"])
    print(f"CONCORDIUM {endpoint.upper()} FAILED (HTTP {status}): {badge}")
    print(f"  {body.get('message', body.get('error', ''))}")
    return 1

def cmd_conc_check_badge(args):
    status, body = _concordium_get("check-badge", args.badge, args.network)
    if status != 200 or not isinstance(body, dict) or "badge_valid" not in body:
        return _concordium_fail("check-badge", args.badge, status, body)
    valid = bool(body["badge_valid"])
    checks = body.get("checks", {})
    audit("concordium:check-badge", args.badge, valid, b"", [] if valid else ["badge_valid=false"])
    print(f"CONCORDIUM BADGE {'VALID' if valid else 'INVALID'}: {args.badge}")
    print(f"  token_id {body.get('token_id')} network {body.get('network')} "
          f"status {body.get('on_chain', {}).get('status')}")
    print(f"  agent_uri {body.get('agent_uri')}")
    print(f"  card_sha256 {body.get('card_sha256')}")
    print(f"  on-chain metadata_hash {body.get('on_chain', {}).get('metadata_hash_hex')}")
    failed = [k for k, v in checks.items() if v is False]
    passed = [k for k, v in checks.items() if v is True]
    print(f"  checks passed {len(passed)}: {', '.join(passed) or 'none'}")
    if failed:
        print(f"  checks FAILED: {', '.join(failed)}")
    for issue in body.get("issues", []):
        print(f"  issue [{issue.get('severity')}]: {issue.get('message')}")
    return 0 if valid else 1

def cmd_conc_verify_card(args):
    status, body = _concordium_get("verify-agent-card", args.badge, args.network)
    if status != 200 or not isinstance(body, dict) or "match" not in body:
        return _concordium_fail("verify-agent-card", args.badge, status, body)
    match = bool(body["match"])
    fetched = body.get("fetched", {})
    audit("concordium:verify-agent-card", args.badge, match, b"",
          [] if match else ["card hash does not match on-chain metadata_hash"])
    print(f"CONCORDIUM CARD HASH {'MATCHES' if match else 'DOES NOT MATCH'} on-chain metadata_hash: {args.badge}")
    print(f"  network {body.get('network')} token_id {body.get('token_id')}")
    print(f"  on-chain uri {body.get('on_chain_uri')}")
    print(f"  on-chain hash {body.get('on_chain_hash_hex')}")
    print(f"  fetched sha256 {fetched.get('sha256_hex')} (HTTP {fetched.get('http_status')}, {fetched.get('byte_length')} bytes)")
    return 0 if match else 1

def cmd_conc_badge_json(args):
    status, body = _concordium_get("get-badge-JSON", args.badge, args.network)
    if status != 200 or not isinstance(body, dict) or "extension" not in body:
        return _concordium_fail("get-badge-JSON", args.badge, status, body)
    audit("concordium:get-badge-JSON", args.badge, True, json.dumps(body).encode())
    print(json.dumps(body, indent=2))
    return 0

# --- concordium contract-info: testnet/mainnet contract indexes ---------
# The registry dApp publishes its per-network contract addresses in a
# runtime config (window.AGENT_REGISTRY_UI_CONFIG) at
# https://agent-registry.concordium.com/config.js — the authoritative
# source for step 2 of the Concordium build plan. This command fetches it
# and cross-checks the values against the MCP service, which stamps its
# expected contracts into every check-badge response. Token-0 badges are
# computed locally: a CIS-2 token address is 0x02 || LEB128(contract index)
# || LEB128(subindex) || token_id as u64 LE, Base58Check-encoded.
CONCORDIUM_DAPP_CONFIG = "https://agent-registry.concordium.com/config.js"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def _leb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def concordium_token_badge(index, subindex, token_id):
    """CIS-2 token address (badge) for a (contract index, subindex, token)
    triple. Verified against two known mainnet badges (see tests)."""
    payload = (b"\x02" + _leb128(index) + _leb128(subindex)
               + int(token_id).to_bytes(8, "little"))
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + digest
    n = int.from_bytes(raw, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58_ALPHABET[r] + s
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + s

def _braced_block(text, start):
    """Return the {...} block starting at index start (which must be '{')."""
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None

def _dapp_config_contracts(text, network):
    """Parse the dApp runtime config; return {"cis8004": (idx, sub),
    "cis8": (idx, sub)} for the requested network. Raises ValueError."""
    m = re.search(rf"\b{re.escape(network)}\s*:\s*\{{", text)
    if not m:
        raise ValueError(f"network {network!r} not found in dApp config")
    block = _braced_block(text, m.end() - 1)
    if block is None:
        raise ValueError(f"network {network!r} block is unbalanced")
    out = {}
    for key, label in (("agentRegistry", "cis8004"), ("cisx", "cis8")):
        km = re.search(rf"\b{key}\s*:\s*\{{", block)
        if not km:
            raise ValueError(f"{key} block missing for {network!r}")
        cblock = _braced_block(block, km.end() - 1)
        im = re.search(r'contractIndex:\s*"(\d+)"', cblock or "")
        sm = re.search(r'contractSubindex:\s*"(\d+)"', cblock or "")
        if not im or not sm:
            raise ValueError(f"contractIndex/Subindex missing in {key} for {network!r}")
        out[label] = (int(im.group(1)), int(sm.group(1)))
    return out

def cmd_conc_contract_info(args):
    network = args.network or "testnet"
    try:
        req = urllib.request.Request(CONCORDIUM_DAPP_CONFIG,
                                     headers={"Accept": "text/javascript,*/*"})
        with urllib.request.urlopen(req, timeout=20) as r:
            config_text = r.read().decode()
    except Exception as e:
        audit("concordium:contract-info", CONCORDIUM_DAPP_CONFIG, False, b"",
              [f"config fetch failed: {e}"])
        print(f"CONCORDIUM CONTRACT-INFO FAILED: could not fetch dApp config: {e}")
        return 1
    try:
        contracts = _dapp_config_contracts(config_text, network)
    except ValueError as e:
        audit("concordium:contract-info", CONCORDIUM_DAPP_CONFIG, False, b"", [str(e)])
        print(f"CONCORDIUM CONTRACT-INFO FAILED: {e}")
        return 1
    cis8004, cis8 = contracts["cis8004"], contracts["cis8"]
    print(f"CONCORDIUM CONTRACTS ({network}): CIS-8004 {cis8004[0]},{cis8004[1]}  CIS-8 {cis8[0]},{cis8[1]}")
    print(f"  source: {CONCORDIUM_DAPP_CONFIG}")
    # Cross-check: the MCP service stamps its expected contracts into every
    # check-badge response. Token 0 exists on testnet and mainnet, so its
    # badge (computed locally, no trust in the config for the id) is the probe.
    badge0 = concordium_token_badge(cis8004[0], cis8004[1], 0)
    try:
        status, body = _concordium_get("check-badge", badge0, network)
    except Exception as e:
        print(f"  cross-check unavailable (check-badge transport error: {e})")
        audit("concordium:contract-info", network, True,
              json.dumps(contracts).encode(), ["mcp cross-check unavailable"])
        return 0
    expected = body.get("expected", {}).get("contracts") if isinstance(body, dict) else None
    if status == 200 and isinstance(expected, dict):
        try:
            exp8004 = tuple(int(x) for x in str(expected.get("cis8004", "")).split(","))
            exp8 = tuple(int(x) for x in str(expected.get("cis8", "")).split(","))
        except ValueError:
            exp8004 = exp8 = None
        ok = exp8004 == cis8004 and exp8 == cis8
        print(f"  cross-check (MCP check-badge {badge0}): {'CONFIRMED' if ok else 'MISMATCH'}"
              f" — MCP expects CIS-8004 {expected.get('cis8004')} CIS-8 {expected.get('cis8')}")
        audit("concordium:contract-info", network, ok,
              json.dumps(contracts).encode(),
              [] if ok else ["dApp config disagrees with MCP expected contracts"])
        return 0 if ok else 1
    print(f"  cross-check unavailable (check-badge HTTP {status}); config values shown without MCP confirmation")
    audit("concordium:contract-info", network, True,
          json.dumps(contracts).encode(), ["mcp cross-check unavailable"])
    return 0

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cardtool", description="A2A agent-card generator/validator/signpost checker")
    ap.add_argument("--version", action="version", version=f"cardtool {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate"); g.add_argument("--out", required=True); g.set_defaults(fn=cmd_generate)
    v = sub.add_parser("validate"); v.add_argument("file"); v.set_defaults(fn=cmd_validate)
    c = sub.add_parser("check-url"); c.add_argument("url"); c.set_defaults(fn=cmd_check_url)
    a = sub.add_parser("accountability", help="hash-chained tamper-evident action log")
    asub = a.add_subparsers(dest="acct_cmd", required=True)
    ai = asub.add_parser("init", help="create an empty hash-chained log (genesis entry)")
    ai.add_argument("--log", required=True); ai.set_defaults(fn=cmd_acct_init, cmd_label="accountability:init")
    aa = asub.add_parser("add", help="append an action entry to the chain")
    aa.add_argument("--log", required=True); aa.add_argument("--action", required=True); aa.add_argument("--detail", required=True)
    aa.set_defaults(fn=cmd_acct_add, cmd_label="accountability:add")
    av = asub.add_parser("verify", help="recompute the whole chain; exit 0 only if intact")
    av.add_argument("--log", required=True); av.add_argument("--head", default=None,
                    help="expected head hash (from export); a mismatch means the log was truncated or extended")
    av.set_defaults(fn=cmd_acct_verify, cmd_label="accountability:verify")
    ae = asub.add_parser("export", help="print a compact summary (entries, head, first/last ts) for embedding")
    ae.add_argument("--log", required=True); ae.set_defaults(fn=cmd_acct_export, cmd_label="accountability:export")
    n = sub.add_parser("concordium", help="read-only checks against the Concordium Agent Registry (CIS-8004)")
    nsub = n.add_subparsers(dest="conc_cmd", required=True)
    nc = nsub.add_parser("check-badge", help="verify a registered agent's badge (on-chain record, card hash, badge form)")
    nc.add_argument("badge", help="CIS-2 token address (Base58Check) or Concordium account")
    nc.add_argument("--network", default=None, choices=["mainnet", "testnet", "devnet"])
    nc.set_defaults(fn=cmd_conc_check_badge, cmd_label="concordium:check-badge")
    nv = nsub.add_parser("verify-card", help="compare a registered agent's live card SHA-256 with its on-chain metadata_hash")
    nv.add_argument("badge"); nv.add_argument("--network", default=None, choices=["mainnet", "testnet", "devnet"])
    nv.set_defaults(fn=cmd_conc_verify_card, cmd_label="concordium:verify-agent-card")
    nb = nsub.add_parser("badge-json", help="fetch the badge block to paste into an agent card")
    nb.add_argument("badge"); nb.add_argument("--network", default=None, choices=["mainnet", "testnet", "devnet"])
    nb.set_defaults(fn=cmd_conc_badge_json, cmd_label="concordium:get-badge-JSON")
    ni = nsub.add_parser("contract-info", help="fetch the registry dApp config and cross-check CIS-8004/CIS-8 contract indexes against the MCP service")
    ni.add_argument("--network", default="testnet", choices=["mainnet", "testnet", "devnet"])
    ni.set_defaults(fn=cmd_conc_contract_info, cmd_label="concordium:contract-info")
    args = ap.parse_args(argv)
    if paused():
        audit(getattr(args, "cmd_label", args.cmd), "PAUSED", False, b"", ["global pause active: ~/workspace/jarvis-lab/PAUSE exists"])
        print("PAUSED: ~/workspace/jarvis-lab/PAUSE exists — doing nothing. Remove that file to resume.")
        return 2
    return args.fn(args)

if __name__ == "__main__":
    sys.exit(main())
