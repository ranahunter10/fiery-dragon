## Summary
<!-- One or two sentences: what changes and why. -->

## 1. What to look at first
<!-- The 3–5 places where a bug would most likely hide, as file:line or function names, each with one line on why. -->
-

## 2. What this PR does not do
<!-- Scope boundaries, follow-ups, known gaps. -->
-

## 3. How it was tested
<!-- The exact command(s) a reviewer runs in a fresh clone, and the pasted output. Say where it ran: hosted CI, container, or VM p15-dev-2604 at snapshot X. -->
```
$ <command>
<output>
```

## 4. Decisions this PR assumes
<!-- ADR numbers, or "none". If it needs a decision that has no ADR yet, stop and write the ADR first. -->
-

## Checklist
- [ ] Single purpose; ≤ ~400 changed lines excluding generated files and evidence (or explained here)
- [ ] Commits follow `area: imperative summary` and are signed off (`git commit -s`)
- [ ] Every new early return, drop, cap or fallback has a counter
- [ ] Record layout changed? Then the schema version is bumped and the generated files are regenerated
- [ ] Every number in the docs links to raw output under `docs/evidence/`
- [ ] `docs/STATE.md` updated if a gate or the next step changed

## Release note
<!-- One line for the changelog, or "none". -->
