# Third-party notices and distribution scope

The original project uses Apache-2.0. The official license is preserved in
`LICENSE`; `NOTICE` is informational and does not invent a copyright owner.
Third-party material retains its own rights and obligations.

| Material | License / source | Handling |
|---|---|---|
| Apache License text | Official Apache Software Foundation text | Unmodified `LICENSE`; its use does not imply ASF sponsorship |
| Developer Certificate of Origin 1.1 | Linux Foundation and contributors' verbatim-copy permission | Official text preserved in `DCO-1.1.txt`; no fabricated contributor certification |
| React Flow (`@xyflow/react` 12.12.1) | MIT, [upstream license](https://github.com/xyflow/xyflow/blob/main/LICENSE) | Exact dependency pin; preserve the bundled upstream license in distributions; interactive graph keeps the accessible table fallback |
| Contributor Covenant 2.1 | CC-BY-4.0, upstream commit `91532d80ea5f39b6685aff4892bc6854bf2f6d6f` | Original text and contemporaneous license preserved; project adaptation changes reporting/contact wording and retains attribution |

The current Contributor Covenant website repository has a different root
license. This project relies on the specifically pinned historical 2.1 release
and its CC-BY-4.0 grant, not on a guessed license for the current website. Exact
URLs, retrieval dates and content hashes are in `source-provenance.json`.

Generate the installed JavaScript dependency inventory with:

```sh
python3 policies/check_dependencies.py --self-test
python3 policies/check_dependencies.py --write
```

`dependency-inventory.json` records exact observed package versions, declared
SPDX expressions, selected options for `OR`, policy decisions and obligations.
The parser handles `AND`, `OR`, `WITH` and parentheses; missing, unknown or
restricted licenses stay unresolved. Exceptions need an exact package/version,
distribution context, owner, expiry, justification and obligations. A scanner
result never changes the upstream license.

This development-host inventory is **not a release SBOM or a complete notice
bundle**. Finished images/packages must also inventory OS/base layers, Python
packages, vendored content, fonts/icons, drivers and model weights, and include
the actual notices required by their contents. Those artifact-level gates remain
open until the actual distributions are built and scanned. Restricted drivers
must be supplied by the operator under their own terms; the open local stack
must remain usable without them.
