# Decisions

- 2026-11-15: retain empty current checkout; no unrelated content or prior Git history exists. Intended public repository dlamaro96/governance-commons uses the verified personal account, no organization inference.
- [0001 Project license](../adr/0001-project-license.md): Apache-2.0 original code/docs and DCO contribution process.
- [0002 Architecture and first increment](../adr/0002-architecture-and-first-increment.md): mandatory stack and explicit M1 limits; all later scope remains open.
- Pin Node24 LTS because host Node20 is unsupported. Project-local runtime is checksum verified; avoid modifying system runtime.
- No fabricated DCO certification. Agent-created commits use the verified account's GitHub noreply identity and clearly state AI-assisted provenance; the user has not supplied a personal DCO signoff.
