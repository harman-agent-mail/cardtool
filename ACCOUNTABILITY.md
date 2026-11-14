# cardtool accountability — design note

Built 2026-11-15 as the core artifact for jarvis's Concordium Trusted Agents
hackathon submission (Checkpoint 1 due 22 Nov 2026). The hackathon's theme is
trusted, verifiable agents; `generate`/`validate`/`check-url` prove what an
agent *claims* to be, and `accountability` proves what an agent *did*.

## Format

An append-only JSONL log. One entry per line, serialised canonically
(`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
UTF-8), so the bytes of any entry are a deterministic function of its content.

Entry fields:

| field    | meaning |
|----------|---------|
| `seq`    | sequence number, 0-based; the genesis entry is seq 0 |
| `ts`     | UTC timestamp, `YYYY-MM-DDTHH:MM:SSZ` |
| `action` | short verb for what happened (e.g. `deploy`, `entered-hackathon`) |
| `detail` | free-text detail |
| `prev`   | SHA-256 of the previous entry; genesis uses 64 zeros |
| `hash`   | SHA-256 over the canonical serialisation of `{seq, ts, action, detail, prev}` |

Commands (all stdlib, no network, PAUSE-respecting, audit-logged like the
rest of cardtool):

- `accountability init --log <path>` — create the log with a genesis entry.
  Refuses to overwrite an existing file (an action history is not disposable).
- `accountability add --log <path> --action <t> --detail <t>` — verify the
  existing chain first, then append. Refuses to extend a broken chain.
- `accountability verify --log <path> [--head <sha256>]` — recompute every
  sequence number, link and hash. Exit 0 + `INTACT: N entries, head <hash>`
  if the chain holds; exit 1 naming the first broken entry otherwise. With
  `--head`, the final hash must also equal the recorded head.
- `accountability export --log <path>` — verify, then print one compact JSON
  line: `{"format":"cardtool-accountability/1","entries":N,"head":<sha256>,
  "first_ts":…,"last_ts":…}` — small enough to embed in an agent card.

## Threat model

Detected by `verify` (chain alone):

- **Editing any field of any past entry** — its recomputed hash no longer
  matches the stored hash; verify names that entry. (Editing the stored
  `hash` too doesn't help: the *next* entry's `prev` then mismatches, and
  fixing that cascades to the head.)
- **Deleting or inserting an entry** — sequence numbers no longer match line
  positions; verify reports the first gap.
- **Reordering entries** — sequence and `prev`-link checks fail at the first
  displaced entry.

Detected only with an externally recorded head (`verify --head <hash>`,
where the hash came from `export` and was stored somewhere the log-writer
can't rewrite — an agent card, a repo commit, an on-chain anchor):

- **Tail truncation** — dropping the last entries leaves a shorter chain that
  is internally valid. A hash chain alone *cannot* detect this; anyone
  claiming otherwise is selling something. The head-anchor is the fix, and
  it is cheap: one 64-char string.
- **Extension/forking after the anchor point** — same mechanism.

NOT detected / out of scope:

- **Wholesale replacement**: an attacker who can rewrite the whole file can
  also recompute a whole new valid chain from genesis. The chain proves
  *internal consistency*, not *authorship*. Authorship needs signatures —
  the natural next step is signing the head hash with the agent's key (for
  the Concordium submission: the agent's on-chain identity), which turns the
  anchored head into a non-repudiable commitment.
- **Lies at write time**: the chain proves entries weren't altered *after*
  being written; it cannot prove an entry was true when written. Garbage
  in, immutably chained garbage. (Mitigation is process, not crypto: entries
  written by the tool at action time, cross-checked against the lab audit
  log, which is hash-stamped per run.)
- **Timestamps** are the writer's clock, unsigned; treat them as claims,
  not proofs.

## Mapping to the Concordium submission

- The demo story: an agent that can be *checked*, not just believed. jarvis
  logs its hackathon-relevant actions (entries, submissions, publications)
  in an accountability log; the exported head is embedded in its agent card
  (`/.well-known/agent-card.json`), so any third party can fetch the card,
  fetch the log, run `verify --head`, and confirm the history they were
  shown is the history that was committed to — no trust in jarvis required.
- On Concordium, the agent's blockchain identity is the authorship anchor
  this design deliberately leaves pluggable: publish/sign the head hash from
  the agent's registered identity and wholesale-replacement attacks die too.
  That integration is the build-window work (19 Nov – 9 Dec); the chain
  itself is chain-agnostic stdlib Python and already final.
- Checkpoint 1 (22 Nov) evidence: this note, the `accountability` commands,
  and 7 new unit tests covering verify-after-adds, middle-entry tampering,
  deletion, anchored truncation, export shape, overwrite refusal, and
  broken-chain append refusal (suite total 14/14).
