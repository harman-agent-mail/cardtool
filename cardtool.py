#!/usr/bin/env python3
"""
cardtool — jarvis's A2A Agent Card generator + validator + signpost checker.

Why this exists (discovered 2026-11-14): of 27,043 indexed ERC-8004 agents,
only 7.60% publish a discoverable /.well-known/agent-card.json (Onchain Agent
Intel, snapshot 2026-11-14T13:29Z). This tool closes that gap for jarvis
first, and works for any agent's card after that.

Stdlib only. $0. No keys. No network except `check-url` (a plain GET of a
public card URL the operator supplies).

Runtime rules baked in, not just documented:
- GLOBAL PAUSE: if ~/workspace/jarvis-lab/PAUSE exists, every command exits 2
  and does nothing except append a `paused` line to the audit log.
- AUDIT: every run appends one JSON line to ~/workspace/jarvis-lab/logs/audit.jsonl
  {ts, cmd, target, ok, sha256_of_card_or_empty, errors}
- NO SECRETS: the validator fails any card whose text contains private-key /
  seed / password patterns.
"""
import argparse, hashlib, json, re, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

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
        "version": "0.2.0",
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

def cmd_check_url(args):
    url = args.url
    if not url.endswith("agent-card.json"):
        url = url.rstrip("/") + "/.well-known/agent-card.json"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            data = r.read()
            status = r.status
    except Exception as e:
        audit("check-url", url, False, b"", [str(e)])
        print(f"SIGNPOST MISSING/UNREACHABLE: {url} ({e})")
        return 1
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

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cardtool", description="A2A agent-card generator/validator/signpost checker")
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
    args = ap.parse_args(argv)
    if paused():
        audit(getattr(args, "cmd_label", args.cmd), "PAUSED", False, b"", ["global pause active: ~/workspace/jarvis-lab/PAUSE exists"])
        print("PAUSED: ~/workspace/jarvis-lab/PAUSE exists — doing nothing. Remove that file to resume.")
        return 2
    return args.fn(args)

if __name__ == "__main__":
    sys.exit(main())
