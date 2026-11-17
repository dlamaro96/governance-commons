// SPDX-License-Identifier: Apache-2.0
import {IMPORT_CSV_HEADERS,IMPORT_LIMITS,type ImportBase,type ImportFormat,type ImportMode,type ImportReady} from '../../../../packages/domain/src/reference-import-contracts.ts';
import type {ReferenceValue} from '../../../../packages/domain/src/reference-data-contracts.ts';
export interface ImportRequest {readonly base:ImportBase;readonly mode:ImportMode;readonly sourceSha256:string}
export function importPath(base:ImportBase,mode:ImportMode){const query=new URLSearchParams({mode,expectedVersion:String(base.expectedVersion)});if(base.publicationHash!==null)query.set('publicationHash',base.publicationHash);return '/reference-data/sets/'+encodeURIComponent(base.setId)+'/import-preview?'+query.toString();}
export function sameImportPreview(value:ImportReady,request:ImportRequest){return value.state==='ready'&&value.base.setId===request.base.setId&&value.base.expectedVersion===request.base.expectedVersion&&value.base.publicationHash===request.base.publicationHash&&value.mode===request.mode&&value.sourceSha256===request.sourceSha256&&value.values.length>=1&&value.values.length<=IMPORT_LIMITS.rows&&value.changes.length<=IMPORT_LIMITS.changes;}
export const importContentType=(format:ImportFormat)=>format==='csv'?'text/csv; charset=utf-8':'application/json; charset=utf-8';
export function importTemplate(format:ImportFormat,ownerId:string){
 const value:ReferenceValue={code:'001',labels:{en:{label:'Example code',description:'Replace every example field before review.'},ar:{label:'رمز نموذجي',description:'استبدل جميع الحقول النموذجية قبل المراجعة.'}},ownerId,status:'active',validFrom:null,validUntil:null};
 if(format==='json')return JSON.stringify({formatVersion:1,kind:'reference-code-rows',values:[value]},null,2)+'\n';
 const quote=(v:string)=>'"'+v.replaceAll('"','""')+'"';return IMPORT_CSV_HEADERS.join(',')+'\r\n'+[value.code,value.labels.en.label,value.labels.en.description,value.labels.ar.label,value.labels.ar.description,ownerId,value.status,'',''].map(quote).join(',')+'\r\n';
}
