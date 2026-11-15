<!-- SPDX-License-Identifier: Apache-2.0 -->
# Attribute-model validation foundation

`src/model.ts` is a dependency-free, deterministic contract for subsequent UI, REST, imports, workflows and MCP integration. It does not execute expressions, access a database, authorize a caller, apply migrations or render rich text. MOD-001/002/003 remain in progress: type inheritance, relation definitions, scoped overrides, lifecycle rules, visual editing, indexed sorting/filtering and migration execution/recovery are not implemented here.

Exports:

- `parseModelDefinition(input: unknown): ValidationResult<ModelDefinition>` validates and defensively copies a plain JSON object into a deeply frozen model.
- `parseModelFile(text: string): ValidationResult<ModelDefinition>` reads a bounded JSON document using the same definition validator, rejecting duplicate keys (including escaped equivalents) before JSON parsing can overwrite them.
- `validateAttributes(model: ModelDefinition, input: unknown): ValidationResult<AttributeValues>` reparses the definition, then validates and copies values without coercion. An invalid definition is reported beneath `/model`; attribute errors use paths such as `/address/city`.
- `previewModelUpgrade(current, proposed, assets): ValidationResult<ModelUpgradePreview>` requires a stable model id and the next integer version. It reports changes, each supplied asset's current/proposed validation issues, affected ids and whether an explicit migration is required. Its coverage is always `provided-assets-only`; the caller must enumerate all authorized tenant assets before making a deployment decision. A successful preview result means the preview ran, not that applying the model is permitted.
- `MODEL_LIMITS`, `URI_SCHEMES` and all public definition, value, issue and preview types are exported.

`ValidationResult<T>` is `{ok:true,value:T}` or `{ok:false,issues:ValidationIssue[]}`. Issues have stable `code`, RFC 6901 JSON Pointer `path` and a message that never embeds a value. Object traversal is sorted; array order is retained. Definitions/values may contain only plain objects with enumerable data properties and dense arrays; getters, symbols, custom prototypes, unknown fields, malformed Unicode and cycles fail validation. No provider input should be represented as an executable JavaScript proxy; decode untrusted transport data as JSON first.

Example model:

```json
{
  "formatVersion": 1,
  "id": "retail.product",
  "version": 1,
  "attributes": {
    "title": {"type": "text", "required": true, "maxLength": 200},
    "price": {"type": "decimal", "precision": 20, "scale": 4},
    "state": {"type": "enum", "values": ["draft", "approved"]},
    "contact": {"type": "object", "properties": {"uri": {"type": "uri", "schemes": ["https"]}}}
  }
}
```

Named attributes may have `required` and `label`. Unknown fields are rejected; `required` means present, and `null` is not a value of any currently supported type. Optional values are omitted, never silently defaulted. Lists use `items`, `minItems` and `maxItems`; their unnamed item schema cannot have a label or required flag. Objects use a closed `properties` map. Names are bounded safe identifiers; prototype-sensitive names are forbidden.

Representations and constraints:

| Type | JSON representation and validation |
| --- | --- |
| `text`, `richText` | String; optional `minLength`/`maxLength` in UTF-16 code units. Rich text is Markdown source. Validation confers no HTML safety: rendering must disable raw HTML or sanitize it separately. |
| `number` | Finite IEEE-754 JSON number; optional `minimum`/`maximum`. `integer:true` additionally requires a safe integer. Negative zero is rejected because JSON serialization loses its sign. Use decimal for exact decimal arithmetic. |
| `decimal` | Canonical string, never converted to a number. No exponent, leading plus/zeros, negative zero or trailing fractional zeros. `precision` counts integer plus fractional positions (excluding the zero before the decimal point); `scale` limits fractional positions. Bounds are canonical decimal strings compared lexically by sign, integer length and padded fraction. |
| `boolean` | Boolean without coercion. |
| `date` | Gregorian `YYYY-MM-DD`, years 0001–9999. |
| `timestamp` | UTC `YYYY-MM-DDTHH:mm:ss[.fraction]Z`, up to nine fractional digits, retained exactly. Offsets, leap seconds and 24:00 are outside this contract's accepted profile. |
| `duration` | Nonnegative ISO 8601 component profile: `PnYnMnDTnHnMnS` or `PnW`, at least one component, integer components up to nine digits, optional seconds fraction up to nine digits. Weeks cannot mix with other components. Calendar months/years are retained; no assumed conversion to elapsed seconds. |
| `enum` | Exact string from a nonempty unique `values` list. |
| `list` | Dense array of recursively validated `items`. |
| `uri` | Absolute ASCII URI, with valid percent escapes and no embedded credentials. Supported schemes: https/http/urn/mailto/s3/gs/abfs/abfss; optional `schemes` narrows that set. `maxLength` can narrow the global string bound. The URI is preserved, not normalized. Network access and rendering still require separate controls. |
| `object` | Closed, recursively validated `properties` map. |

Bounds are fixed, never tenant-controlled: schema depth 8; 2,048 schema nodes; 128 properties per object; 1,000 list items; 256 enum values; 65,536 UTF-16 units per scalar and 1,048,576 per validation; 20,000 value nodes; 100 issues; 262,144 UTF-16 units per model file. Preview accepts up to 1,000 assets and 100,000 combined validation nodes, with a combined string budget and at most 1,000 nested asset issues. Resource-limit failures are explicit and do not return a partial preview as success.

The upgrade preview flags attribute removal and type changes at every nesting level, including list items, as requiring migration even with zero supplied assets. Enum-value removal and URI-scheme removal also require migration. Other tightened constraints require migration when any supplied current/proposed attributes fail validation. No migration flag or model version bypasses these findings. The preview does not prove transactional rollback, complete asset enumeration or authorization; those must be implemented and verified in the persistence/workflow layers.

Run the adversarial, precision, bounds and upgrade tests from the repository root with `pnpm test`; the root TypeScript check includes this module through its test imports. These unit tests qualify only the library behavior, not UI/API consistency or release readiness.
