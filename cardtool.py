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

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cardtool", description="A2A agent-card generator/validator/signpost checker")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate"); g.add_argument("--out", required=True); g.set_defaults(fn=cmd_generate)
    v = sub.add_parser("validate"); v.add_argument("file"); v.set_defaults(fn=cmd_validate)
    c = sub.add_parser("check-url"); c.add_argument("url"); c.set_defaults(fn=cmd_check_url)
    args = ap.parse_args(argv)
    if paused():
        audit(args.cmd, "PAUSED", False, b"", ["global pause active: ~/workspace/jarvis-lab/PAUSE exists"])
        print("PAUSED: ~/workspace/jarvis-lab/PAUSE exists — doing nothing. Remove that file to resume.")
        return 2
    return args.fn(args)

if __name__ == "__main__":
    sys.exit(main())
