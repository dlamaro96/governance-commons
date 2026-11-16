// SPDX-License-Identifier: Apache-2.0
import { admitAuthorityInput, parseAuthorityInputFile } from '../../authority/src/admission.ts';
import { canonicalDecisionJSON, decisionInvalid } from '../../authority/src/decision-schema.ts';
import type { AuthorityIssue } from '../../authority/src/types.ts';
export type Validator=(v:unknown,p:string)=>unknown;
export type Row=Record<string,unknown>;
export function fail(message:string,code:AuthorityIssue['code']='scope'):never{return decisionInvalid(code,'',message);}
export const equal=(a:unknown,b:unknown,message:string):void=>{if(canonicalDecisionJSON(a)!==canonicalDecisionJSON(b))fail(message);};
export const str:Validator=(v,p)=>{if(typeof v!=='string')decisionInvalid('type',p,'Expected string.');return v;};
export const uuid:Validator=(v,p)=>{const s=str(v,p) as string;if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)||s==='00000000-0000-0000-0000-000000000000')decisionInvalid('format',p,'Expected nonnil canonical UUID.');return s;};
export const digest:Validator=(v,p)=>{const s=str(v,p) as string;if(!/^[0-9a-f]{64}$/.test(s))decisionInvalid('format',p,'Expected SHA256.');return s;};
export const integer=(min=0,max=Number.MAX_SAFE_INTEGER):Validator=>(v,p)=>{if(!Number.isSafeInteger(v)||Object.is(v,-0)||(v as number)<min||(v as number)>max)decisionInvalid('range',p,'Expected bounded integer.');return v;};
export const version=integer(1,2147483647);
export const counter:Validator=(v,p)=>{const s=str(v,p) as string;if(!/^[1-9][0-9]{0,18}$/.test(s)||BigInt(s)>9223372036854775807n)decisionInvalid('format',p,'Expected positive bigint decimal.');return s;};
export const utc:Validator=(v,p)=>{const s=str(v,p) as string;if(!/^[0-9]{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s)||s.startsWith('0000')||!Number.isFinite(Date.parse(s))||new Date(s).toISOString()!==s)decisionInvalid('format',p,'Expected canonical UTC millisecond timestamp.');return s;};
export const literal=(...values:unknown[]):Validator=>(v,p)=>{if(!values.includes(v))decisionInvalid('unsupported',p,'Unknown closed value.');return v;};
export const nullable=(f:Validator):Validator=>(v,p)=>v===null?null:f(v,p);
export const row=(v:unknown,p=''):Row=>{if(v===null||typeof v!=='object'||Array.isArray(v))decisionInvalid('type',p,'Expected object.');return v as Row;};
export const shape=(fields:Record<string,Validator>):Validator=>(v,p)=>{const r=row(v,p);for(const key of Object.keys(r))if(!Object.hasOwn(fields,key))decisionInvalid('unknown_field',p,'Unknown field.');return Object.freeze(Object.fromEntries(Object.entries(fields).map(([k,f])=>{if(!Object.hasOwn(r,k))decisionInvalid('required',p,'Missing field.');return [k,f(r[k],p.length<800?`${p}/${k}`:p)];})));};
export const array=(item:Validator,key:(v:unknown)=>string,max=262144):Validator=>(v,p)=>{if(!Array.isArray(v))decisionInvalid('type',p,'Expected array.');if(v.length>max)decisionInvalid('limit',p,'Array exceeds profile.');let last:string|undefined;return Object.freeze(v.map(x=>{const value=item(x,p),k=key(value);if(last!==undefined&&last>=k)decisionInvalid(last===k?'duplicate':'format',p,'Expected distinct canonical ordering.');last=k;return value;}));};
export const ref=shape({id:uuid,version});
export const grantRef=shape({kind:literal('grant','delegation','elevation'),id:uuid,version:literal(1)});
export const validity:Validator=(v,p)=>{const r=shape({notBefore:nullable(utc),expiresAt:nullable(utc)})(v,p) as Row;if(r.notBefore!==null&&r.expiresAt!==null&&(r.notBefore as string)>=(r.expiresAt as string))decisionInvalid('range',p,'Invalid validity interval.');return r;};
export function admitted(value:unknown){const result=typeof value==='string'?parseAuthorityInputFile(value):admitAuthorityInput(value);if(!result.ok)decisionInvalid(result.issues[0]!.code,result.issues[0]!.path,result.issues[0]!.message);return result.value;}
/** Foundation scalars are narrower than the shared pure engine grammar. Input is detached JSON. */
export function foundationScalars(value:unknown):void{
 const uuidKeys=new Set(['tenantId','identityId','roleId','policyId','domainId','assignmentId','effectiveGrantId','sessionId','issuingRegistrationId','issuerRegistrationId','identityBindingId','registryId','ruleId','groupId']);
 const uuidArrays=new Set(['groupIds','domainIds','ids']);
 function visit(v:unknown,key:string,parent:Row|null):void{
  if(typeof v==='string'){
   if(key!=='document'&&/[\u0000-\u001f\u007f]/.test(v))fail('Canonical text contains control characters.','format');
   if(uuidKeys.has(key)||uuidArrays.has(key)||key==='id'&&parent!==null&&!Object.hasOwn(parent,'branch'))uuid(v,'');
   if(['identityRevision','revision','generation','authorityEpoch','authnFenceEpoch','securityRevision'].includes(key)&&/^[0-9]+$/.test(v))counter(v,'');
   if(['notBefore','expiresAt','authenticatedAt','issuedAt','asOf'].includes(key))utc(v,'');
   return;
  }
  if(Array.isArray(v)){for(const x of v)visit(x,key,null);return;}
  if(v===null||typeof v!=='object')return;
  for(const [k,x]of Object.entries(v))visit(x,k,v as Row);
 }
 visit(value,'',null);
}
