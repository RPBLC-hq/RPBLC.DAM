---
command: remember
description: Review session and capture learnings in MEMORY.md
version: 1.0
---

# Remember — Session Learning Capture

Review the current session and distill learnings into the auto memory file for future sessions.

**Target file:** `$HOME/.claude/projects/c--Dev-RPBLC-DAM/memory/MEMORY.md`

## Safety Rules

This project will be published publicly. Before writing anything to memory:

- **NEVER** include real names, emails, API keys, paths containing usernames, or any PII
- **NEVER** include internal URLs, private repo names, or org-specific details
- **NEVER** reference private conversations, business context, or unreleased plans
- **DO** use generic examples: `user@example.com`, `/path/to/project`, `some-org/repo`
- **DO** focus on technical patterns, Rust idioms, crate behaviors, and build gotchas
- When in doubt, omit it

## When to Use

- End of productive sessions
- After discovering crate API quirks or Rust edition gotchas
- After mistakes that wasted time and should be avoided
- After successful patterns worth repeating
- After dependency updates or build system changes

## Workflow

### 1. Session Review

Analyze the conversation and identify:

| Category | Look For |
|----------|----------|
| **Technical Discoveries** | Crate API quirks, Rust edition behavior, compiler/clippy rules |
| **Build & Dependency Issues** | Version conflicts, feature flags, compilation gotchas |
| **Architecture Decisions** | Patterns chosen, trade-offs made, crate boundaries |
| **Mistakes Made** | Errors that required correction, wrong assumptions |
| **Successful Approaches** | Efficient solutions, clean patterns, good test strategies |

### 2. Evaluate Significance

Only capture learnings that are:
- [ ] Likely to recur in future sessions
- [ ] Not already documented in MEMORY.md
- [ ] Specific enough to be actionable (include crate names, versions, exact syntax)
- [ ] General enough to apply beyond the one instance
- [ ] Safe to publish (no PII, no private context)

### 3. Update MEMORY.md

Read the current MEMORY.md and update the appropriate sections. Keep it under 200 lines (content beyond line 200 gets truncated in the system prompt). If approaching the limit, consolidate older entries or move detailed notes to separate topic files (e.g., `debugging.md`, `patterns.md`) linked from MEMORY.md.

Sections to maintain:

```markdown
## Project Overview
[High-level facts about the codebase]

## Key Technical Details
[Crate versions, API quirks, edition-specific behavior]

## Build Commands
[Exact commands that work]

## Common Pitfalls
[Things that waste time if you don't know them]
```

### 4. Verification

- [ ] No PII, usernames, private URLs, or org-specific details
- [ ] No duplicate entries
- [ ] Entries are concise and include versions/specifics
- [ ] Test count is updated if tests were added
- [ ] MEMORY.md stays under 200 lines

## Output Format

After updating MEMORY.md, summarize:

```markdown
## Session Learnings Captured

**Added:**
- [item]

**Updated:**
- [item]

**Removed (outdated):**
- [item]
```

## Example Learnings

**Good (specific, actionable):**
- "reqwest 0.12 with `stream` feature requires `futures-util` for `StreamExt`"
- "axum `Response::builder()` returns `Builder`, not `Result` — chain `.header()` calls directly"
- "SSE events are `\n\n`-delimited but also check `\r\n\r\n` for Windows"

**Bad (too vague or leaks info):**
- "HTTP stuff was tricky"
- "Fixed the bug John reported"
- "Updated the internal dashboard at company.com/admin"
