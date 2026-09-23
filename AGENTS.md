# AGENTS.md

Instructions for AI coding agents working in this repository. Read this file
fully and run the startup check before any code work.

## Delegation policy

Always prefer opencode-bridge MCP (`ask_opencode`) over native subagents. If
opencode-bridge tools are absent, halt and report diagnostics. Never silently
substitute with own subagents.

## Startup check — do this first, before any code work

1. List available MCP tools. Confirm `opencode-bridge` is connected with:
   `ask_opencode`, `list_opencode_models`, `zen_chat`. Confirm `brig` is
   connected with: `index`, `search_symbols`, `get_symbol`, `get_outline`,
   `callers_callees`, `blast_radius`, `check_refs`.
2. If present: run `list_opencode_models` with `freeOnly=true` to verify the
   `opencode` CLI works, then use `ask_opencode` (default:
   `opencode/muse-spark-1.3-contributor-free` @ `xhigh`) for delegated work.
   Prefer the bridge over spawning your own subagents.
3. Call it with the real parameter names — `prompt, model, directory, agent,
   variant, timeoutSecs`. There is no `reasoning_effort` parameter; unknown
   params are silently ignored. For any implementation task set
   `timeoutSecs: 600` (default is only 180) and split implement vs. test into
   separate calls.
4. If a call times out, read the metadata before concluding the bridge is
   broken. Growing `events/steps/tool_calls` with large `stdout_chars` means
   the run was healthy but over budget — split scope or raise `timeoutSecs`
   and retry. A fast failure with `429/rate limit/capacity` means tier
   contention — the bridge already retries those; just re-call. Only treat
   hangs with no progress, crashes, or connection errors as bridge malfunction.
5. If missing/failed: STOP. Do NOT silently fall back to Task/subagents. Tell
   the user which MCP servers are visible, the exact bridge error, and the fix:
   `npm run build` in `/Users/user/Documents/GitHub/cline`, verify
   `node dist/index.js` + `opencode models` work, check the client MCP config
   points at `/Users/user/Documents/GitHub/cline/dist/index.js`, then restart
   the client. Wait for the user before burning usage on workarounds.

## brig — investigate through the index before reading files

`brig` is a deterministic tree-sitter code-graph index (SQLite, no embeddings)
exposed as MCP tools and as the `brig` CLI (`uv run --directory
/Users/user/Documents/GitHub/context-mcp brig …`). One index per repo
(`brig index . --slug <name>`); re-index after big changes. Output is JSON with
a `_meta` envelope — cite `_meta` scan counts when claiming absence, never
hallucinate negatives.

Locate code in this order, cheapest first:

1. `search_symbols` for the identifier or concept.
2. `get_symbol` / `get_outline` to pin exact location and signature — byte
   offsets from the index are authoritative, never guess spans.
3. `callers_callees` (depth ≤ 3) or `blast_radius` when the task asks about
   impact or usage. `check_refs` to confirm a reference before deleting.
4. Fetch exact slices instead of whole-file reads; run `blast_radius` before
   edits.

Work in the three brig roles (source: `/Users/user/Documents/GitHub/context-mcp/skills/`):

- **investigator** (read-only, never edits): report one finding per line as
  `path:line — symbol — ≤6 words`. If the index returns nothing, output exactly
  `No match.` (plus scan counts when claiming absence). Findings feed the plan;
  they are not an implementation order.
- **builder** (executes a plan file, nothing else): 1–2 files max per step,
  tests green after every step, end each change with a receipt line
  `path:line-range — change`. No drive-by refactors or out-of-scope files.
  Terminal refusal lines, copied exactly, end the step: `too-big. split:`,
  `needs-confirm. op:`, `ambiguous. ask:`.
- **reviewer** (read-only, never edits): check the diff against the plan line
  by line. Output `verdict: accept | request-changes` plus one evidence line
  per hunk: `path:line-range — plan L<N>: <quote-or-paraphrase> — in-scope |
  out-of-scope`. Out-of-scope hunks or missing/failed verification force
  `request-changes`.

## Secrets — never leak

- Never print, echo, quote, commit, or transmit secrets: API keys, tokens,
  passwords, cookies, certificates/private keys, `.env` contents, connection
  strings.
- Never include secrets in `ask_opencode` / `zen_chat` prompts — those leave
  this machine.
- Reference secrets by env-var name, never by value. Redact anything that
  looks like a credential before pasting into chat, files, or commit messages.
- This repo captures live network traffic: packet payloads and logs may
  contain credentials. Treat captured data as sensitive; sanitize pcaps before
  committing test fixtures.

## Red-team tooling & detection testing

- Long-term vision: this workspace may grow red-team (offensive) modules. Their
  first-class purpose is testing our own defenses (purple teaming): an attack
  generator feeds the sensor and the test asserts the detection fires.
- HARD RULE: red-team/attack tooling runs ONLY against networks and hosts the
  user owns or has explicit authorization to test — never third-party systems.
  Refuse tasks that ask otherwise.
- Every detection must ship with a test: synthetic fixtures now, red-module
  generated traffic later.
- Do not start red-team crates until the blue core (phases 1–2) is complete;
  keep them out of scope in commits and PRs until then.

## Git — commit per change

- After every implemented feature, fix, or docs change, commit it — one
  logical change per commit, prefixed:
  - `feat:` — new feature or capability
  - `fix:` — bug fix
  - `docs:` — documentation
- Tests must pass before a `feat:`/`fix:` commit.
- Never commit `PLAN.md` or other local planning notes — they stay untracked
  (see `.gitignore`).
- End every commit message with:

  ```
  Co-Authored-By: Claude <noreply@anthropic.com>
  ```
