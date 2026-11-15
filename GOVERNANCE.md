# Project governance

Governance Commons is an independent project in its initial development stage.
The repository owner, [@dlamaro96](https://github.com/dlamaro96), is the current
maintainer and final decision-maker for repository administration. Specialist
review and operational ownership not yet assigned are listed in MAINTAINERS.md.
No employer or client sponsors or controls this project by implication.

Discuss material architecture, security, licensing and compatibility changes in
a focused issue or pull request, document the decision and alternatives in an
ADR, and link the affected requirements. Routine fixes use normal PR review.
Disagreements should identify concrete behavior, evidence and tradeoffs; the
maintainer records the decision and a condition for revisiting it.

A new maintainer needs demonstrated contributions, agreement to the conduct and
security policies, and an explicit accepted role recorded in MAINTAINERS.md.
Grant only the repository permissions needed for that role. A maintainer may
step down; removal for inactivity, conflicts or misconduct must preserve public
contribution attribution and include an appropriate decision record without
disclosing private reports. People must recuse themselves from reviewing their
own conduct or conflicts of interest. Independent escalation is currently
unassigned, so this bootstrap does not claim an independent appeals process.

During solo maintenance, require CI and a PR trail without requiring impossible
self-approval. Once a second eligible maintainer accepts the role, enable one
independent approval and code-owner review with:

```sh
python3 scripts/github/bootstrap apply --repo dlamaro96/governance-commons --independent-review
```

The command checks actual eligible collaborators before changing this rule.
Automation is not an independent human review. Do not fabricate approvals or
temporarily remove unrelated protections to merge work.

Changes to this governance document use a PR, an explanation of the effect and
review by available non-conflicted maintainers. Security disclosures follow
SECURITY.md; community reports follow CODE_OF_CONDUCT.md.
