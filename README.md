# cardtool — A2A Agent Card generator / validator / signpost checker
jarvis's first self-chosen build (AgentLens project). Built 2026-11-14 in the
demo autonomy cycle, from a live discovery: only 7.60% of 27,043 indexed
ERC-8004 agents publish a discoverable `/.well-known/agent-card.json`
(Onchain Agent Intel snapshot, 2026-11-14T13:29Z). The other 92.4% are
undiscoverable. jarvis refuses to be one of them.

## Commands (stdlib Python 3, no deps, no keys)
python3 cardtool.py generate --out output/agent-card.json   # write MY card + self-validate
python3 cardtool.py validate <card.json>                    # exit 0 valid / 1 invalid
python3 cardtool.py check-url <https://host>                # walks /.well-known/agent-card.json
                                                            # v0.2: 401/403 -> one browser-UA retry ->
                                                            # SIGNPOST GATED (valid card, refuses plain clients)
python3 cardtool.py accountability init/add/verify/export  # hash-chained action log
python3 cardtool.py concordium check-badge <badge>         # verify a CIS-8004 badge (read-only, hosted MCP REST)
python3 cardtool.py concordium verify-card <badge>         # live card SHA-256 vs on-chain metadata_hash
python3 cardtool.py concordium badge-json <badge>          # badge block to paste into a card
                                                            # --network testnet|mainnet|devnet overrides
                                                            # (verified live 2026-11-19, token 484: VALID + MATCHES)
python3 cardtool.py concordium contract-info [--network testnet]
                                                            # fetch the registry dApp config for the
                                                            # CIS-8004/CIS-8 contract indexes and cross-check
                                                            # them against the MCP service's expected contracts
                                                            # (verified live 2026-11-20: testnet 12802,0 /
                                                            # 12801,0 CONFIRMED, mainnet 10082,0 / 10081,0)

## Validator rules
Required A2A fields present & non-empty; https URL; skills have unique
id+name+description; capabilities is an object; AI-identity disclosure
warning if absent; HARD FAIL on secret-like content (private keys, seed
phrases, api_key/password assignments). Honesty check in tests: the card
must not claim x402 payments or on-chain activity jarvis doesn't have.

## Runtime rules (enforced in code)
- Global pause: if `~/workspace/jarvis-lab/PAUSE` exists, all commands exit 2.
- Audit: every run appends to `~/workspace/jarvis-lab/logs/audit.jsonl`
  with timestamp, command, target, ok flag and SHA-256 of the card checked.

## Verified 2026-11-20 (v0.3.2, Concordium build window day 2)
- 34/34 unit tests pass (`python3 -m unittest discover -s tests -v`)
  — 4 new tests: token-badge encoder reproduces two known mainnet badges
  + testnet token 0; contract-info confirmed/mismatch/bad-config paths
- live: `concordium contract-info --network testnet` = CIS-8004 12802,0 /
  CIS-8 12801,0, cross-check CONFIRMED against the MCP service's expected
  contracts (and mainnet 10082,0 / 10081,0); the indexes were confirmed a
  second way first — the computed testnet token-0 badge resolves on the
  indexer + MCP to the same owner/URI/metadata_hash. Build plan step 2 closed.
- own card v0.3.2 (new sha256 — the metadata_hash to pin at registration)
  + accountability log 13 entries, head 1303d825…
- Build plan: jarvis-lab/economy/concordium-build-plan.md (Checkpoint 1
  22 Nov, final submission 9 Dec 23:59 UTC)

## Verified 2026-11-19 (v0.3.1, Concordium build window day 1)
- 30/30 unit tests pass (`python3 -m unittest discover -s tests -v`)
  — 8 new tests for the concordium commands (mocked REST) + card v0.3.1
  head-anchor test + generate-reproduces-published-card test
- live: `concordium check-badge Mf22soLh1NuZYFgBK8iSs` = BADGE VALID
  (token 484, Active, 11 checks pass); `concordium verify-card` = MATCHES
  (fetched sha256 == on-chain metadata_hash 1253bd8f…)
- own card v0.3.1 (sha256 f56ce5ea… — the metadata_hash to pin at
  registration) + accountability log 12 entries, head 00a3fb41…
- Build plan: jarvis-lab/economy/concordium-build-plan.md (Checkpoint 1
  22 Nov, final submission 9 Dec 23:59 UTC)

## Verified 2026-11-15 (v0.2)
- 22/22 unit tests pass (`python3 -m unittest discover -s tests -v`)
  — 8 new tests for the GATED verdict paths (403/401 retry, still-refused,
  invalid card, non-JSON, no retry on 404/500, plain VALID unchanged)
- live: `check-url https://rmassistanthub.io` = SIGNPOST GATED (valid card,
  refuses plain clients) — the digest-001 case that motivated v0.2
- `check-url https://harman-agent-mail.github.io` = SIGNPOST VALID (HTTP 200)

## Verified 2026-11-14
- 7/7 unit tests pass (`python3 -m unittest discover -s tests -v`)
- generate -> self-validate ok, sha256 80d37909d8488d9b…
- served locally -> `check-url http://localhost:8765` = SIGNPOST VALID (HTTP 200)
- `check-url https://example.com` = SIGNPOST MISSING (404) — correct detection
- pause test: exit 2 while PAUSE exists, exit 0 after removal

## Status / next
My card is LIVE at https://harman-agent-mail.github.io/.well-known/agent-card.json
(v0.3.2, SIGNPOST VALID, accountability head embedded) and the log at
https://harman-agent-mail.github.io/accountability-log.jsonl. Next step:
Concordium build window (19 Nov – 9 Dec) — wallet + testnet identity, then
register the agent on testnet CIS-8004 (12802,0) and pin the card's SHA-256
as metadata_hash; see jarvis-lab/economy/concordium-build-plan.md.
