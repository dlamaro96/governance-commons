// SPDX-License-Identifier: Apache-2.0
// Private inactive storage DTOs. Neither a parsed closure nor its hash is authority.
import type { Counter, Digest, UUID, UTC, Validity, Version } from '../../authority/src/types.ts';
import type { AtomicRequest, AuthorityGrant, DefinitionEvidence, GrantRef, GroupEvidence,
  GroupMembershipEvidence, MembershipRef, PolicyEvidence, PrincipalEvidence, PrincipalGroups } from '../../authority/src/decision-types.ts';
export type ClosureSelectors = {formatVersion:1;requests:readonly AtomicRequest[]};
export type ClosureKey = Digest;
export type ClosurePartition = {key:ClosureKey;subject:{kind:'human';id:UUID};request:AtomicRequest;candidates:readonly GrantRef[]};
export type ClosureParent = {child:GrantRef;parent:GrantRef;viaMembership:MembershipRef|null};
export type ClosureDependency = {from:ClosureKey;issuer:ClosureKey;child:GrantRef};
export type LifecycleHead = {family:'definition'|'group-membership'|'grant'|'elevation-use';id:UUID;definitionKind:'policy'|'role'|'responsibility-type'|'group'|null;headVersion:Version};
export type FoundationSession = {formatVersion:1;sessionId:UUID;sessionVersion:Version;identityId:UUID;tenantId:UUID;generation:Counter;authnFenceEpoch:Counter;issuingRegistrationId:UUID;issuerRegistrationId:UUID;identityBindingId:UUID;authenticatedAt:UTC;issuedAt:UTC;expiresAt:UTC};
export type ElevationUseRecord = {ref:MembershipRef;elevation:GrantRef;identityId:UUID;sessionId:UUID;sessionVersion:Version;generation:Counter;state:'active'|'revoked';validity:Validity};
export type FoundationLoadMetrics = {selectors:number;partitions:number;dependencyEdges:number;dependencyReferences:number;dependencyDepth:number;canonicalBytes:number;jsonNodes:number;maxDepth:number;policies:number;policyBytes:number;policyRules:number;expressionNodes:number;ordinaryOrigins:number;connectedRecords:number;principals:number;directGroupsMaximum:number;proofBytes:number};
export type AuthorityHumanClosure = {
 formatVersion:1;kind:'inactive-human-candidate-closure';contentAuthority:false;session:FoundationSession;
 snapshot:{tenantId:UUID;generation:Counter;authorityEpoch:Counter;registryId:UUID;registryVersion:Version;registryDigest:Digest;asOf:UTC;identityRevisionDigest:Digest;closureDigest:Digest};
 selectors:readonly AtomicRequest[];partitions:readonly ClosurePartition[];parents:readonly ClosureParent[];dependencies:readonly ClosureDependency[];
 principals:readonly Extract<PrincipalEvidence,{kind:'human'}>[];groups:readonly GroupEvidence[];memberships:readonly GroupMembershipEvidence[];principalGroups:readonly PrincipalGroups[];
 definitions:readonly DefinitionEvidence[];policies:readonly PolicyEvidence[];grants:readonly Exclude<AuthorityGrant,{kind:'service'}>[];elevationUses:readonly ElevationUseRecord[];lifecycleHeads:readonly LifecycleHead[];metrics:FoundationLoadMetrics;
};
export interface NativeOwnerConnection {query(text:string,values?:unknown[]):Promise<{rows:unknown[]}>;release(error?:boolean):void}
export interface NativeOwnerPool {connect():Promise<NativeOwnerConnection>}
export type AuthorityFoundationErrorCode='AUTHORITY_FOUNDATION_INPUT_INVALID'|'AUTHORITY_FOUNDATION_EXECUTOR_REJECTED'|'AUTHORITY_FOUNDATION_SESSION_REJECTED'|'AUTHORITY_FOUNDATION_VERSION_CONFLICT'|'AUTHORITY_FOUNDATION_PROFILE_LIMIT'|'AUTHORITY_FOUNDATION_INTEGRITY'|'AUTHORITY_FOUNDATION_DEADLINE';
export class AuthorityFoundationError extends Error {
 constructor(readonly code:AuthorityFoundationErrorCode){super(code);this.name='AuthorityFoundationError';}
}
