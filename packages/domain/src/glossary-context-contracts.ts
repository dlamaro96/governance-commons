// SPDX-License-Identifier: Apache-2.0
/** A summary of an approved term through one independently visible defines link.
 * This view never includes the full publication or its other linked resources. */
export interface AssetGlossaryContextItem {
 termId:string;termVersion:number;relationId:string;locale:string;
 name:string;definition:string;state:string;
}
export interface AssetGlossaryContextPage {
 assetId:string;items:AssetGlossaryContextItem[];nextCursor:string|null;
}
