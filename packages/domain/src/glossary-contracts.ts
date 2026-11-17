// SPDX-License-Identifier: Apache-2.0
import type {AttributeValues, ValidationResult} from './model.ts';
import type {AssetTypeDefinition} from './asset-type.ts';

/** Publication data only. Identity, membership, current permissions and stored
 * pins are established by the application transaction, never by this payload. */
export const GLOSSARY_LIMITS=Object.freeze({translations:32,aliases:32,examples:16,
  name:240,definition:16_384,example:4096,links:100,allowedIdentities:100,bytes:262_144});
export interface GlossaryTranslation {
  readonly locale:string;
  readonly name:string;
  readonly definition:string;
  readonly synonyms:readonly string[];
  readonly abbreviations:readonly string[];
  readonly examples:readonly string[];
}
export interface GlossaryTypePin {
  readonly typeId:string;
  readonly modelId:string;
  readonly version:number;
  readonly definitionHash:string;
  readonly resolutionHash:string;
}
export interface GlossaryRelationPin {
  readonly relationTypeId:string;
  readonly version:number;
  readonly definitionHash:string;
}
/** An authored full target set, not an instruction to erase unrelated edges.
 * Only links owned by the prior glossary publication may be replaced. */
export interface GlossaryLink {
  readonly kind:'broader'|'related'|'defines';
  readonly typePin:GlossaryRelationPin;
  readonly targetAssetId:string;
  readonly targetAssetVersion:number;
}
export interface GlossaryPublicationInput {
  readonly typePin:GlossaryTypePin;
  readonly primaryLocale:string;
  readonly ownerId:string;
  readonly visibility:'tenant'|'restricted';
  readonly allowedIdentityIds:readonly string[];
  readonly state:'active'|'deprecated';
  /** Must include the typed translations list. Additional attributes are
   * validated against the exact published asset-type model. */
  readonly attributes:AttributeValues;
  readonly links:readonly GlossaryLink[];
}
export interface ParsedGlossaryPublication {
  readonly input:GlossaryPublicationInput;
  readonly translations:readonly GlossaryTranslation[];
  readonly name:string;
  readonly description:string;
  /** Locale-qualified comparison keys; never evidence of visibility, identity
   * equivalence or permission to merge two terms. */
  readonly aliases:readonly {locale:string;kind:'name'|'synonym'|'abbreviation';value:string;key:string}[];
}
export type GlossaryPublicationParser=(input:unknown)=>ValidationResult<ParsedGlossaryPublication>;
export type GlossaryStarterTypeFactory=()=>AssetTypeDefinition;
