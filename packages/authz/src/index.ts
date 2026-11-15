// SPDX-License-Identifier: Apache-2.0
export type Principal={id:string;name:string;tenantId:string;permissions:string[]};
export function permits(principal:Principal,action:string):boolean{return principal.permissions.includes(action);}
export function canView(principal:Principal,resource:{tenantId:string;visibility:string;allowedIdentities?:string[]}):boolean{
 return permits(principal,'catalog:read') && principal.tenantId===resource.tenantId && (resource.visibility==='tenant'||(resource.allowedIdentities??[]).includes(principal.id));
}
export class Problem extends Error {constructor(public status:number,public code:string,message:string,public issues?:readonly {code:string;path:string;message:string}[]){super(message);}}
export function requirePermission(p:Principal,action:string){if(!permits(p,action))throw new Problem(403,'FORBIDDEN','Your current permissions do not allow this action.');}
