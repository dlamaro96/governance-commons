// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseGlossaryGraphSourceProof, validateGlossaryGraphSource, type GlossaryGraphSourceProof } from '../../packages/domain/src/relation-glossary-source.ts';
import { validateFinalRelationGraphConstraints } from '../../packages/domain/src/relation-participation.ts';
import { a,b,c,actor,id,relationId,asset,edge,binding,graph,policy,definition,ok,fails } from './relation-participation-fixtures.ts';
const proof = (changes: Partial<GlossaryGraphSourceProof> = {}): GlossaryGraphSourceProof => ({formatVersion:1,publicationId:id(800),requestId:id(801),tenantId:id(802),actorId:actor,
 relationTypeIds:[relationId],beforeEndpoint:null,afterEndpoint:asset(a),...changes});
const positive = policy(definition({sourceStates:['draft'],targetStates:['active'],cardinality:{outgoing:{min:1,max:1},incoming:{min:0,max:null}}}));
const newBefore = () => graph({endpoints:[asset(a),asset(b,{state:'active'})],edges:[],bindings:[]});

test('protected source restores an absent new term while ordinary graph validation refuses missing required participation',()=>{
 const before=newBefore(), sourceProof=proof(), original=structuredClone({before,policies:[positive],sourceProof});
 fails(validateFinalRelationGraphConstraints({graph:before,policies:[positive]}),'required');
 const restored=ok(validateGlossaryGraphSource(original));
 assert.deepEqual(restored.endpoints,[asset(b,{state:'active'})]);assert.deepEqual(restored.edges,[]);assert.deepEqual(restored.bindings,[]);
 assert.deepEqual(original,{before,policies:[positive],sourceProof});assert.ok(Object.isFrozen(restored.endpoints));
});

test('protected lifecycle source restores only the old endpoint and current observation versions',()=>{
 const sourceProof=proof({beforeEndpoint:asset(a),afterEndpoint:asset(a,{assetVersion:2,state:'active'})});
 const policies=[policy(definition({sourceStates:['draft']}))];
 const before=graph({endpoints:[sourceProof.afterEndpoint,asset(b)],edges:[edge(a,b,{sourceAssetVersion:2})],bindings:[binding(a,'source',{assetVersion:2})]});
 fails(validateFinalRelationGraphConstraints({graph:before,policies}),'invalid_definition');
 const restored=ok(validateGlossaryGraphSource({before,policies,sourceProof}));
 assert.deepEqual(restored,graph({bindings:[binding()]}));
});

test('unrelated corrupt cohorts cannot be excused by a valid new term proof',()=>{
 const before=graph({endpoints:[asset(a),asset(b,{state:'active'}),asset(c)],edges:[],bindings:[]});
 fails(validateGlossaryGraphSource({before,policies:[positive],sourceProof:proof()}),'required');
 const cyclePolicy=policy(definition({cycles:'acyclic'}));
 const cycle=graph({endpoints:[asset(a),asset(b),asset(c)],edges:[edge(b,c),edge(c,b,{key:{kind:'existing',relationId:id(101)}})]});
 fails(validateGlossaryGraphSource({before:cycle,policies:[cyclePolicy],sourceProof:proof()}),'cycle');
});

test('a new-term proof cannot erase existing incident edges or participation',()=>{
 fails(validateGlossaryGraphSource({before:graph(),policies:[policy()],sourceProof:proof()}),'invalid_definition','/sourceProof/beforeEndpoint');
 fails(validateGlossaryGraphSource({before:graph({edges:[],bindings:[binding()]}),policies:[policy()],sourceProof:proof()}),'invalid_definition','/sourceProof/beforeEndpoint');
});

test('the actual after endpoint and exact complete type scope are mandatory',()=>{
 const input={before:newBefore(),policies:[positive],sourceProof:proof()};
 fails(validateGlossaryGraphSource({...input,sourceProof:proof({afterEndpoint:asset(c)})}),'invalid_definition','/sourceProof/afterEndpoint');
 fails(validateGlossaryGraphSource({...input,sourceProof:proof({relationTypeIds:[]})}),'invalid_definition','/sourceProof/relationTypeIds');
 fails(parseGlossaryGraphSourceProof(proof({relationTypeIds:[relationId,relationId]})),'duplicate');
 fails(parseGlossaryGraphSourceProof(proof({relationTypeIds:[id(9),relationId]})),'invalid_definition');
});

test('proof does not authorize pin changes, skipped versions or illegal lifecycle changes',()=>{
 for(const after of [asset(a,{assetVersion:3}),asset(a,{assetVersion:2,state:'retired'}),asset(b,{assetVersion:2})])
  assert.equal(parseGlossaryGraphSourceProof(proof({beforeEndpoint:asset(a),afterEndpoint:after})).ok,false);
 const different=asset(a,{assetVersion:2,typeId:id(55)});
 fails(parseGlossaryGraphSourceProof(proof({beforeEndpoint:asset(a),afterEndpoint:different})),'invalid_definition');
 fails(parseGlossaryGraphSourceProof(proof({afterEndpoint:asset(a,{state:'active'})})),'model_version');
 ok(parseGlossaryGraphSourceProof(proof({beforeEndpoint:asset(a),afterEndpoint:asset(a,{assetVersion:2})})));
});

test('stale edge and binding observations cannot be silently rewritten into a source proof',()=>{
 const sourceProof=proof({beforeEndpoint:asset(a),afterEndpoint:asset(a,{assetVersion:2,state:'active'})});
 const before=graph({endpoints:[sourceProof.afterEndpoint,asset(b)],bindings:[binding()]});
 fails(validateGlossaryGraphSource({before,policies:[policy()],sourceProof}),'model_version','/before/edges');
 fails(validateGlossaryGraphSource({before:{...before,edges:[edge(a,b,{sourceAssetVersion:2})]},policies:[policy()],sourceProof}),'model_version','/before/bindings');
});

test('proof admission detaches values and refuses unknown fields, accessors, duplicates and bounds',()=>{
 const input=proof(), parsed=ok(parseGlossaryGraphSourceProof(input));assert.notEqual(parsed,input);assert.ok(Object.isFrozen(parsed.afterEndpoint));
 fails(parseGlossaryGraphSourceProof({...input,skipSourceValidation:true}),'unknown_field');
 let touched=false;const accessor={...input};Object.defineProperty(accessor,'beforeEndpoint',{enumerable:true,get(){touched=true;return null;}});
 fails(parseGlossaryGraphSourceProof(accessor),'invalid_json');assert.equal(touched,false);
 fails(parseGlossaryGraphSourceProof({...input,publicationId:'invalid'}),'format');
 assert.equal(parseGlossaryGraphSourceProof({...input,relationTypeIds:Array.from({length:5001},(_,i)=>id(i+1000))}).ok,false);
 assert.equal(validateGlossaryGraphSource({before:newBefore(),policies:[positive],sourceProof:{...input,extra:'x'.repeat(524289)}}).ok,false);
});

import { constructGlossaryRelationGraphProposal, validateGlossaryRelationGraphChange, constructRelationGraphProposal, validateRelationGraphChange, parseGraphChangeSet } from '../../packages/domain/src/relation-migration.ts';
import type { AuthorizedCompleteGraphChange } from '../../packages/domain/src/relation-migration-contracts.ts';
import { plan, values } from './relation-participation-fixtures.ts';
function pendingPublication(){
 const before=newBefore(),sourceProof=proof();
 const changeSet={formatVersion:1 as const,relationTargets:[{kind:'repair' as const,expectedHeadVersion:1,definition:null,
  plan:plan({sourceVersions:[],edges:[],creations:[{key:'approved_link',sourceAssetId:a,targetAssetId:b,sourceAssetVersion:1,targetAssetVersion:1,values:values()}]})}],assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null};
 const input={changeSet,before,policies:[positive],preparedAssets:{policies:[],changes:[],typeMigrations:[]},proposedEndpoints:before.endpoints};
 const authorized=(proposed:AuthorizedCompleteGraphChange['proposed']):AuthorizedCompleteGraphChange=>({changeSet,before,policies:[positive],preparedAssets:input.preparedAssets,
  proposed,completeRelationTypeIds:[relationId],activeOwnerIds:new Set([actor]),tenantMemberIds:new Set([actor]),actorId:actor});
 return {input,sourceProof,authorized};
}
test('protected construction enrolls a new required participant and final validation proves its real degree',()=>{
 const {input,sourceProof,authorized}=pendingPublication();
 assert.equal(constructRelationGraphProposal(input).ok,false);
 const proposed=ok(constructGlossaryRelationGraphProposal(input,sourceProof));
 assert.equal(proposed.edges.length,1);assert.equal(proposed.bindings.length,1);assert.equal(proposed.bindings[0].key.kind,'enrollment');
 assert.equal(validateRelationGraphChange(authorized(proposed)).ok,false);
 const result=ok(validateGlossaryRelationGraphChange(authorized(proposed),sourceProof));assert.equal(result.changedEdges[0].action,'create');assert.equal(result.changedBindings[0].action,'enroll');
});

test('protected source evidence never excuses an incomplete final degree, forged projection or wrong actor',()=>{
 const {input,sourceProof,authorized}=pendingPublication(), withoutLink={...input,changeSet:{...input.changeSet,relationTargets:[{...input.changeSet.relationTargets[0],plan:plan({sourceVersions:[],edges:[],creations:[]})}]}};
 const invalidFinal=ok(constructGlossaryRelationGraphProposal(withoutLink,sourceProof));
 fails(validateGlossaryRelationGraphChange({...authorized(invalidFinal),changeSet:withoutLink.changeSet},sourceProof),'range');
 const valid=ok(constructGlossaryRelationGraphProposal(input,sourceProof));
 fails(validateGlossaryRelationGraphChange(authorized({...valid,edges:[]}),sourceProof),'invalid_definition','/migration/proposed');
 fails(validateGlossaryRelationGraphChange(authorized(valid),{...sourceProof,actorId:id(9)}),'invalid_definition','/sourceProof/actorId');
});

test('protected wrappers refuse graph definition publication and caller fields while public plan parser is unchanged',()=>{
 const {input,sourceProof}=pendingPublication();
 const publication={...input,changeSet:{...input.changeSet,relationTargets:[{kind:'publish' as const,expectedHeadVersion:1,definition:definition({version:2}),plan:input.changeSet.relationTargets[0].plan}]},policies:[positive,policy(definition({version:2}))]};
 assert.equal(constructGlossaryRelationGraphProposal(publication,sourceProof).ok,false);
 fails(parseGraphChangeSet({...input.changeSet,sourceProof}),'unknown_field');
 assert.equal(constructGlossaryRelationGraphProposal(input,undefined as never).ok,false);
 let touched=false;const bad={...sourceProof};Object.defineProperty(bad,'beforeEndpoint',{enumerable:true,get(){touched=true;return null;}});
 assert.equal(constructGlossaryRelationGraphProposal(input,bad).ok,false);assert.equal(touched,false);
});

test('protected lifecycle repair can remove obsolete participation but never preserve invalid endpoints',()=>{
 const sourceProof=proof({beforeEndpoint:asset(a),afterEndpoint:asset(a,{assetVersion:2,state:'active'})});
 const pinned=policy(definition({sourceStates:['draft'],cardinality:{outgoing:{min:1,max:1},incoming:{min:0,max:null}}}));
 const before=graph({endpoints:[sourceProof.afterEndpoint,asset(b,{state:'active'})],edges:[edge(a,b,{sourceAssetVersion:2})],bindings:[binding(a,'source',{assetVersion:2})]});
 const changeSet={formatVersion:1 as const,relationTargets:[{kind:'repair' as const,expectedHeadVersion:1,definition:null,
  plan:plan({edges:[{relationId:id(100),expectedVersion:1,action:'tombstone',reason:'Approved lifecycle change'}],bindings:[{bindingId:id(200),expectedVersion:1,action:'release',reason:'No longer eligible'}]})}],assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null};
 const input={changeSet,before,policies:[pinned],preparedAssets:{policies:[],changes:[],typeMigrations:[]},proposedEndpoints:before.endpoints};
 const proposed=ok(constructGlossaryRelationGraphProposal(input,sourceProof));
 const authorized={changeSet,before,policies:[pinned],preparedAssets:input.preparedAssets,proposed,completeRelationTypeIds:[relationId],activeOwnerIds:new Set([actor]),tenantMemberIds:new Set([actor]),actorId:actor};
 ok(validateGlossaryRelationGraphChange(authorized,sourceProof));
 const preserved={...input,changeSet:{...changeSet,relationTargets:[{...changeSet.relationTargets[0],plan:plan({edges:[{relationId:id(100),expectedVersion:1,action:'preserve'}],bindings:[{bindingId:id(200),expectedVersion:1,action:'preserve'}]})}]}};
 const bad=ok(constructGlossaryRelationGraphProposal(preserved,sourceProof));
 fails(validateGlossaryRelationGraphChange({...authorized,changeSet:preserved.changeSet,proposed:bad},sourceProof),'invalid_definition');
});
