// SPDX-License-Identifier: Apache-2.0
// Host-only pure controls. No DB, HTTP, browser or product publication is performed.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import type {Result} from '../../packages/domain/src/reference-data-contracts.ts';
import type {CrosswalkDefinition,HierarchyDefinition,StructureProposal,EndpointValidationContext,PublishedStructure,StructureDefinition} from '../../packages/domain/src/reference-structure-contracts.ts';
import {STRUCTURE_CSV_COLUMNS} from '../../packages/domain/src/reference-structure-contracts.ts';
import {parseRelease,parseProposal,parseProposalJSON,parseApprovalPayload,approvalDigestPreimage,proposalDigest,
 parsePublishedBundle,publish,publicationHash,serializeBundle,parseBundleCSV,parsePublicationResult} from '../../packages/domain/src/reference-structure.ts';
const id=(n:number)=>'11111111-1111-4111-8111-'+String(n).padStart(12,'0');
const now='2026-11-20T10:00:00.000Z',later='2026-11-21T10:00:00.000Z',end='2026-11-22T10:00:00.000Z';
const labels={en:{label:'Categories',description:'Reference structure'},ar:{label:'الفئات',description:'بنية مرجعية'}};
const source={setId:id(1),version:1,publicationHash:'a'.repeat(64)},target={setId:id(2),version:1,publicationHash:'b'.repeat(64)};
const mapping=(sourceCode='A',targetCode='X')=>({sourceCode,targetCode,relation:'equivalent' as const,method:'steward-asserted' as const,methodDetails:'Reviewed by the steward',transformationNotes:'Use the exact code; no transformation is executed.',confidence:{kind:'not-assessed' as const},validFrom:null,validUntil:null});
const crosswalk:CrosswalkDefinition={formatVersion:1,kind:'reference-crosswalk',labels,ownerId:id(3),status:'active',activation:{kind:'on-publication'},validUntil:null,source,target,cardinality:'many-to-many',overlapPolicy:'reject-overlapping-pair',mappings:[mapping()]};
const hierarchy:HierarchyDefinition={formatVersion:1,kind:'reference-hierarchy',labels,ownerId:id(3),status:'active',activation:{kind:'on-publication'},validUntil:null,reference:source,multiParent:'forbid',edges:[{parentCode:'P',childCode:'A',validFrom:null,validUntil:null}]};
const proposal=(release:StructureDefinition=crosswalk):StructureProposal=>({id:id(5),structureId:id(6),expectedVersion:0,release,workflow:{id:'reference_review',version:1,definitionHash:'c'.repeat(64)},assignments:{reviewer:id(4)},expiresAt:'2026-11-21T00:00:00.000Z'});
const contexts:EndpointValidationContext[]=[{pin:source,releaseStatus:'active',publishedAt:'2026-11-19T00:00:00.000Z',effectiveFrom:'2026-11-19T00:00:00.000Z',declaredValidUntil:null,nextKnownEffectiveFrom:null,codes:['P','Q','A','B','X','Y'].map(code=>({code,status:'active',validFrom:null,validUntil:null}))},{pin:target,releaseStatus:'active',publishedAt:'2026-11-19T00:00:00.000Z',effectiveFrom:'2026-11-19T00:00:00.000Z',declaredValidUntil:null,nextKnownEffectiveFrom:null,codes:['X','Y'].map(code=>({code,status:'active',validFrom:null,validUntil:null}))}];
function ok<T>(value:Result<T>):T{assert.equal(value.ok,true,value.ok?'':JSON.stringify(value.issues));if(!value.ok)throw Error('not ok');return value.value;}
function invalid(value:Result<unknown>,code?:string){assert.equal(value.ok,false);if(!value.ok&&code)assert.equal(value.issues[0].code,code);}
const payload=(release:StructureDefinition,expectedVersion=0)=>({formatVersion:1 as const,kind:'reference-structure-publication' as const,structureId:id(6),expectedVersion,release});
function publication(release:StructureDefinition=crosswalk,overrides:Record<string,unknown>={}){return publish({payload:payload(release),publishedAt:now,previous:null,endpoints:release.kind==='reference-hierarchy'?[contexts[0]]:contexts,...overrides});}
const clone=<T>(v:T):T=>structuredClone(v);

test('closed definitions normalize descriptive EN/AR text while preserving literal code order and meaning',()=>{
 const parsed=ok(parseRelease({...crosswalk,labels:{...labels,en:{label:'  Cafe\u0301  ',description:' Line one\nline two '}},mappings:[mapping('a','Y'),mapping('01','X'),mapping('A','X')]}));
 assert.equal(parsed.labels.en.label,'Café');assert.equal(parsed.labels.en.description,'Line one\nline two');assert.equal(parsed.kind,'reference-crosswalk');if(parsed.kind==='reference-crosswalk')assert.deepEqual(parsed.mappings.map(row=>row.sourceCode),['01','A','a']);
 invalid(parseRelease({...crosswalk,mappings:[mapping(' A','X')]}),'FORMAT');invalid(parseRelease({...crosswalk,mappings:[mapping('é','X')]}),'FORMAT');
});
test('original lengths and controls cannot disappear through trim or NFC',()=>{
 for(const label of [' '.repeat(241)+'A','\nA','A\t','A\u0085'])invalid(parseRelease({...hierarchy,labels:{...labels,en:{label,description:'Allowed'}}}),'FORMAT');
 ok(parseRelease({...hierarchy,labels:{...labels,en:{label:'A',description:'First\nSecond\tThird'}}}));
 invalid(parseRelease({...hierarchy,labels:{...labels,en:{label:'A',description:'Allowed\u000bNo'}}}),'FORMAT');
 invalid(parseRelease({...crosswalk,mappings:[{...mapping(),transformationNotes:' '.repeat(2049)+'x'}]}),'FORMAT');
});
test('closed policy, confidence, pins and version bounds refuse ambiguous shapes',()=>{
 for(const value of [{...crosswalk,source:{...source,setId:'00000000-0000-0000-0000-000000000000'}},{...crosswalk,target:source},{...crosswalk,overlapPolicy:'first-match'},{...crosswalk,cardinality:'one-to-one'},{...crosswalk,unreviewed:true},{...crosswalk,mappings:[{...mapping(),method:'inferred'}]},{...crosswalk,mappings:[{...mapping(),confidence:{kind:'declared',basisPoints:10001,basis:'x'}}]},{...crosswalk,mappings:[{...mapping(),confidence:{kind:'not-assessed',basisPoints:0}}]}])invalid(parseRelease(value));
 invalid(parseProposal({...proposal(),expectedVersion:2147483647},id(3)),'LIMIT');ok(parseProposal({...proposal(),expectedVersion:2147483646},id(3)));
 invalid(parseProposal({...proposal(),expectedVersion:-0},id(3)),'INVALID_JSON');
});
test('safe data snapshots reject accessors, proxies, toJSON, cycles, symbols and sparse arrays without execution',()=>{
 let calls=0;const accessor=clone(crosswalk);Object.defineProperty(accessor,'labels',{enumerable:true,get(){calls++;return labels;}});invalid(parseRelease(accessor));
 const proxy=new Proxy({}, {ownKeys(){calls++;return [];},getPrototypeOf(){calls++;return null;}});invalid(parseRelease(proxy));
 const toJSON={...crosswalk,toJSON(){calls++;return crosswalk;}};invalid(parseRelease(toJSON));
 const cycle:any={...crosswalk};cycle.labels=cycle;invalid(parseRelease(cycle));
 invalid(parseRelease({...crosswalk,[Symbol('hidden')]:true}));invalid(parseRelease({...crosswalk,mappings:new Array(1)}));
 invalid(parseRelease({...crosswalk,mappings:Object.assign([mapping()],{private:true})}));assert.equal(calls,0);
});
test('aggregate UTF8 and collection bounds fail rather than truncating valid-looking entries',()=>{
 invalid(parseRelease({...crosswalk,mappings:Array.from({length:257},(_,i)=>mapping('C'+i,'X'))}),'LIMIT');
 invalid(parseRelease({...crosswalk,mappings:Array.from({length:80},(_,i)=>({...mapping('C'+i,'X'),transformationNotes:'ع'.repeat(2000)}))}),'LIMIT');
 const result=ok(parseRelease({...crosswalk,mappings:Array.from({length:256},(_,i)=>mapping('C'+String(i).padStart(3,'0'),'X'))}));
 assert.equal(result.kind,'reference-crosswalk');if(result.kind==='reference-crosswalk')assert.equal(result.mappings.length,256);
});
test('overlapping same-pair mappings reject conflicts and duplicates; many-to-many and adjacency remain valid',()=>{
 invalid(parseRelease({...crosswalk,mappings:[mapping(),mapping()]}),'CONFLICT');
 invalid(parseRelease({...crosswalk,mappings:[{...mapping(),validUntil:later},{...mapping(),relation:'source-broader',validFrom:now}]}),'CONFLICT');
 const result=ok(parseRelease({...crosswalk,mappings:[{...mapping(),validUntil:later},{...mapping(),validFrom:later},mapping('A','Y'),mapping('B','X')]}));
 assert.equal(result.kind,'reference-crosswalk');if(result.kind==='reference-crosswalk')assert.equal(result.mappings.length,4);
});
test('hierarchy validation checks temporal slices rather than an invalid union-only cycle test',()=>{
 invalid(parseRelease({...hierarchy,edges:[{parentCode:'A',childCode:'A',validFrom:null,validUntil:null}]}),'CONFLICT');
 const temporal:HierarchyDefinition={...hierarchy,multiParent:'allow',edges:[{parentCode:'A',childCode:'B',validFrom:null,validUntil:later},{parentCode:'B',childCode:'A',validFrom:later,validUntil:null}]};
 ok(publication(temporal));invalid(publication({...temporal,edges:[temporal.edges[0],{...temporal.edges[1],validFrom:'2026-11-21T09:59:59.999Z'}]}),'CONFLICT');
 invalid(parseRelease({...hierarchy,edges:[{parentCode:'A',childCode:'B',validFrom:null,validUntil:null},{parentCode:'B',childCode:'P',validFrom:null,validUntil:null},{parentCode:'P',childCode:'A',validFrom:null,validUntil:null}]}),'CONFLICT');
});
test('explicit multi-parent policy applies at each active interval and never disables cycles',()=>{
 const edges=[{parentCode:'P',childCode:'A',validFrom:null,validUntil:null},{parentCode:'Q',childCode:'A',validFrom:null,validUntil:null}];
 invalid(publication({...hierarchy,edges}),'CONFLICT');ok(publication({...hierarchy,multiParent:'allow',edges}));
 ok(publication({...hierarchy,edges:[{...edges[0],validUntil:later},{...edges[1],validFrom:later}]}));
 invalid(publication({...hierarchy,multiParent:'allow',edges:[...edges,{parentCode:'A',childCode:'P',validFrom:null,validUntil:null}]}),'CONFLICT');
});
test('bounded chain validates all 256 nodes and refuses depth257',()=>{
 const code=(i:number)=>'N'+String(i).padStart(3,'0'),edges=Array.from({length:255},(_,i)=>({parentCode:code(i),childCode:code(i+1),validFrom:null,validUntil:null}));
 const endpoint={...contexts[0],codes:Array.from({length:256},(_,i)=>({code:code(i),status:'active' as const,validFrom:null,validUntil:null}))};
 ok(publication({...hierarchy,edges},{endpoints:[endpoint]}));invalid(parseRelease({...hierarchy,edges:[...edges,{parentCode:code(255),childCode:code(256),validFrom:null,validUntil:null}]}),'LIMIT');
});
test('disconnected hierarchy nodes share the same 256-code bound across all temporal slices',()=>{
 const edges=Array.from({length:128},(_,i)=>({parentCode:'P'+i,childCode:'C'+i,validFrom:null,validUntil:later}));
 ok(parseRelease({...hierarchy,edges}));
 invalid(parseRelease({...hierarchy,edges:[...edges,{parentCode:'NEW_PARENT',childCode:'NEW_CHILD',validFrom:later,validUntil:null}]}),'LIMIT');
 invalid(parseRelease({...hierarchy,edges:Array.from({length:256},(_,i)=>({parentCode:'P'+i,childCode:'C'+i,validFrom:null,validUntil:null}))}),'LIMIT');
});
test('publication resolves the canonical clock and protects complete immutable endpoint identity',()=>{
 const first=ok(publication());assert.equal(first.effectiveFrom,now);assert.equal(first.version,1);assert.ok(Object.isFrozen(first));const original=JSON.stringify(first),originalHash=ok(publicationHash(first));
 const second=ok(publication({...crosswalk,activation:{kind:'at',at:end}},{payload:payload({...crosswalk,activation:{kind:'at',at:end}},1),previous:first,publishedAt:later}));assert.equal(second.version,2);assert.equal(second.effectiveFrom,end);
 invalid(publication(crosswalk,{payload:payload(crosswalk,0),previous:first}),'CONFLICT');
 invalid(publication({...crosswalk,source:target,target:source},{payload:payload({...crosswalk,source:target,target:source},1),previous:first,publishedAt:later}),'CONFLICT');
 invalid(publication(hierarchy,{payload:payload(hierarchy,1),previous:first,publishedAt:later}),'CONFLICT');
 invalid(publication({...crosswalk,activation:{kind:'at',at:now}}),'CONFLICT');
 assert.equal(JSON.stringify(first),original);assert.equal(ok(publicationHash(first)),originalHash);assert.equal(crosswalk.mappings[0].sourceCode,'A');
});
test('endpoint hashes, existence, membership and active state are validated before a new bundle derives',()=>{
 for(const endpoints of [contexts.slice(0,1),[contexts[0],contexts[0]],[contexts[0],{...contexts[1],pin:{...target,publicationHash:'d'.repeat(64)}}],[contexts[0],{...contexts[1],releaseStatus:'deprecated' as const}],[contexts[0],{...contexts[1],codes:[{code:'Z',status:'active' as const,validFrom:null,validUntil:null}]}],[contexts[0],{...contexts[1],codes:contexts[1].codes.map(c=>({...c,status:'deprecated' as const}))}],[contexts[0],{...contexts[1],publishedAt:later,effectiveFrom:later}]])invalid(publication(crosswalk,{endpoints}),'CONFLICT');
 ok(publication(crosswalk,{endpoints:[contexts[1],contexts[0]]}));
});
test('known endpoint successor bounds require a finite contained structure interval',()=>{
 const endpoints=[{...contexts[0],nextKnownEffectiveFrom:later},contexts[1]];
 invalid(publication(crosswalk,{endpoints}),'INTERVAL');ok(publication({...crosswalk,validUntil:later},{endpoints}));
 invalid(publication({...crosswalk,validUntil:end},{endpoints}),'INTERVAL');
 invalid(publication({...crosswalk,validUntil:later,mappings:[{...mapping(),validUntil:end}]},{endpoints}),'INTERVAL');
 invalid(publication({...crosswalk,mappings:[{...mapping(),validFrom:'2026-11-19T00:00:00.000Z'}]}),'INTERVAL');
});
test('future endpoint publications can support scheduled structures after their exact start',()=>{
 const endpoints=contexts.map(c=>({...c,effectiveFrom:later}));
 invalid(publication(crosswalk,{endpoints}),'INTERVAL');
 const result=ok(publication({...crosswalk,activation:{kind:'at',at:later}},{endpoints}));assert.equal(result.effectiveFrom,later);
 invalid(publication({...crosswalk,activation:{kind:'at',at:later}},{endpoints:contexts.map(c=>({...c,publishedAt:end,effectiveFrom:end}))}),'CONFLICT');
});
test('code-specific intervals must cover each complete mapping without implicit clipping',()=>{
 const endpoints=[{...contexts[0],codes:contexts[0].codes.map(c=>({...c,validFrom:later,validUntil:end}))},contexts[1]];
 invalid(publication(crosswalk,{endpoints}),'INTERVAL');
 ok(publication({...crosswalk,mappings:[{...mapping(),validFrom:later,validUntil:end}]},{endpoints}));
 invalid(publication({...crosswalk,mappings:[{...mapping(),validFrom:later}]},{endpoints}),'INTERVAL');
});
test('proposal digest binds request ID, workflow pin, assignment, expiry, complete mappings and structure identity',()=>{
 const original=proposal(),base=ok(proposalDigest(original,id(3)));
 for(const candidate of [{...original,id:id(7)},{...original,structureId:id(8)},{...original,workflow:{...original.workflow,version:2}},{...original,assignments:{reviewer:id(9)}},{...original,expiresAt:end},{...original,release:{...crosswalk,mappings:[{...mapping(),confidence:{kind:'declared' as const,basisPoints:9000,basis:'Reviewed against the source definition'}}]}}])assert.notEqual(ok(proposalDigest(candidate,id(3))),base);
 const preimage=ok(approvalDigestPreimage(original,id(3)));assert.equal(preimage.binding,'reference.structure.publish');assert.equal(preimage.payload.structureId,original.structureId);
 invalid(parseProposal({...original,assignments:{one:id(4),two:id(4)}},id(3)),'FORMAT');invalid(parseProposal({...original,assignments:{one:id(3)}},id(3)),'FORMAT');
});
test('duplicate raw JSON keys, reserved escaped keys and exact timestamps reject before normalization',()=>{
 const raw=JSON.stringify(proposal());ok(parseProposalJSON(raw,id(3)));invalid(parseProposalJSON(raw.replace('"expectedVersion":0','"expectedVersion":0,"expectedVersion":0'),id(3)),'INVALID_JSON');
 invalid(parseProposalJSON(raw.replace('"expectedVersion":0','"expectedVersion":0,"\\u005f\\u005fproto__":{}'),id(3)));
 for(const expiresAt of ['2026-02-30T00:00:00.000Z','0000-01-01T00:00:00.000Z','2026-11-21T00:00:00Z','2026-11-21T00:00:00.000+00:00'])invalid(parseProposal({...proposal(),expiresAt},id(3)),'FORMAT');
});
test('stored bundles refuse reordering, normalization changes, backdating and extra fields',()=>{
 const b=ok(publication({...crosswalk,mappings:[mapping('A','Y'),mapping('A','X')]}));assert.equal(b.kind,'reference-crosswalk');
 if(b.kind==='reference-crosswalk')invalid(parsePublishedBundle({...b,mappings:[...b.mappings].reverse()}),'NON_CANONICAL');
 invalid(parsePublishedBundle({...b,labels:{...labels,en:{...labels.en,label:' Categories '}}}),'NON_CANONICAL');
 invalid(parsePublishedBundle({...b,effectiveFrom:'2026-11-19T00:00:00.000Z'}),'INTERVAL');invalid(parsePublishedBundle({...b,activation:{kind:'on-publication'}}),'FIELDS');
});
test('maximum-byte immediate and scheduled bundles retain their original activation budget',()=>{
 function atLimit(activation:CrosswalkDefinition['activation']):CrosswalkDefinition{
  const mappings=Array.from({length:128},(_,i)=>({...mapping('C'+String(i).padStart(3,'0'),'X'),transformationNotes:'x'}));
  const release:CrosswalkDefinition={...crosswalk,activation,mappings};
  let remaining=245760-Buffer.byteLength(JSON.stringify(release),'utf8');
  assert.ok(remaining>0);
  for(const row of mappings){const added=Math.min(2047,remaining);row.transformationNotes+='x'.repeat(added);remaining-=added;}
  assert.equal(remaining,0);assert.equal(Buffer.byteLength(JSON.stringify(release),'utf8'),245760);return release;
 }
 const endpoints=[{...contexts[0],codes:Array.from({length:128},(_,i)=>({code:'C'+String(i).padStart(3,'0'),status:'active' as const,validFrom:null,validUntil:null}))},contexts[1]];
 const immediate=atLimit({kind:'on-publication'}),scheduled=atLimit({kind:'at',at:later});
 const first=ok(publication(immediate,{endpoints})),second=ok(publication(scheduled,{endpoints}));
 assert.equal(first.effectiveFrom,first.publishedAt);assert.equal(second.effectiveFrom,later);
 assert.deepEqual(ok(parsePublishedBundle(first)),first);assert.deepEqual(ok(parsePublishedBundle(second)),second);
 // Keeping immediate maximum-size rows while inserting a later activation
 // would exceed the approved definition budget, even if the bundle cap fits.
 invalid(parsePublishedBundle({...first,effectiveFrom:later}),'LIMIT');
 invalid(parseRelease({...immediate,activation:{kind:'at',at:later}}),'LIMIT');
});
test('CSV and JSON representations retain exact Arabic, commas, quotes, CRLF and confidence',()=>{
 const b=ok(publication({...crosswalk,labels:{...labels,ar:{label:'الفئات، "خاص"',description:'السطر الأول\nالسطر الثاني'}},mappings:[{...mapping(),methodDetails:'Manual, "review"',transformationNotes:'Line1\r\nLine2, "literal"',confidence:{kind:'declared',basisPoints:0,basis:'Explicitly assessed; not a probability'}}]}));
 const csv=ok(serializeBundle(b,'csv')),json=ok(serializeBundle(b,'json'));assert.equal(STRUCTURE_CSV_COLUMNS.length,29);assert.deepEqual(ok(parseBundleCSV(csv.body)),b);assert.deepEqual(ok(parsePublishedBundle(JSON.parse(json.body))),b);assert.equal(csv.byteLength,Buffer.byteLength(csv.body));assert.notEqual(csv.etag,json.etag);
 assert.equal(csv.etag,'"'+createHash('sha256').update('gc-reference-structure-csv-v1\0'+csv.body).digest('hex')+'"');assert.equal(csv.etag,ok(serializeBundle(b,'csv')).etag);
});
test('empty hierarchy and crosswalk releases preserve metadata and policy in complete exports',()=>{
 for(const d of [{...hierarchy,edges:[]},{...crosswalk,mappings:[]}] as StructureDefinition[]){const b=ok(publication(d)),csv=ok(serializeBundle(b,'csv'));assert.deepEqual(ok(parseBundleCSV(csv.body)),b);assert.equal(csv.body.split('\r\n').length,3);assert.ok(csv.body.includes(b.structureId));}
});
test('CSV parser refuses truncation, duplicate metadata, substituted coordinate, nonapplicable fields and hash forgery',()=>{
 const b=ok(publication()),csv=ok(serializeBundle(b,'csv')).body,lines=csv.split('\r\n');
 const alteredHeader=csv.replace('recordType,schemaVersion','recordType,recordType');
 for(const raw of [csv.slice(0,-2),csv+'\r\n',alteredHeader,lines.slice(0,2).concat(lines[1],...lines.slice(2)).join('\r\n'),csv.replace(id(6),id(7)),csv.replace(ok(publicationHash(b)),'e'.repeat(64)),csv.replace(/\r\n/g,'\n'),csv+'\ud800'])invalid(parseBundleCSV(raw));
 // Insert an ignored-looking owner on an entry row: exact reserialization must refuse it.
 const quotedRow=lines[2].split(',');quotedRow[7]=id(9);invalid(parseBundleCSV([lines[0],lines[1],quotedRow.join(','),''].join('\r\n')));
});
test('CSV parser closes duplicate JSON cells and wrong record families',()=>{
 const b=ok(publication(hierarchy)),csv=ok(serializeBundle(b,'csv')).body;
 invalid(parseBundleCSV(csv.replace('hierarchy-edge','crosswalk-mapping')),'FORMAT');
 invalid(parseBundleCSV(csv.replace('""setId"":','""setId"":""'+source.setId+'"",""setId"":')),'INVALID_JSON');
 invalid(parseBundleCSV(csv.replace('release,1,reference-hierarchy','release,01,reference-hierarchy')),'FORMAT');
});
test('complete maximum-size export keeps the last mapping rather than serializing a page',()=>{
 const mappings=Array.from({length:256},(_,i)=>mapping('C'+String(i).padStart(3,'0'),'X')),endpoints=[{...contexts[0],codes:mappings.map(r=>({code:r.sourceCode,status:'active' as const,validFrom:null,validUntil:null}))},contexts[1]];
 const b=ok(publication({...crosswalk,mappings},{endpoints})),csv=ok(serializeBundle(b,'csv')),roundtrip=ok(parseBundleCSV(csv.body));assert.equal(roundtrip.kind,'reference-crosswalk');if(roundtrip.kind==='reference-crosswalk'){assert.equal(roundtrip.mappings.length,256);assert.equal(roundtrip.mappings[255].sourceCode,'C255');}
});
test('context objects cannot execute getters and each trusted endpoint projection remains bounded',()=>{
 let calls=0;const c:any={payload:payload(crosswalk),publishedAt:now,previous:null,endpoints:contexts};Object.defineProperty(c,'payload',{enumerable:true,get(){calls++;return payload(crosswalk);}});invalid(publish(c));assert.equal(calls,0);
 invalid(publication(crosswalk,{endpoints:[{...contexts[0],codes:[...contexts[0].codes,contexts[0].codes[0]]},contexts[1]]}),'DUPLICATE');
 invalid(publication(crosswalk,{endpoints:[{...contexts[0],extra:true},contexts[1]]}),'FIELDS');
});
test('publication receipt validates the exact new binding without accepting existing family result shapes',()=>{
 const b=ok(publication()),result={binding:'reference.structure.publish',structureId:b.structureId,version:b.version,publicationHash:ok(publicationHash(b)),publishedAt:b.publishedAt,effectiveFrom:b.effectiveFrom};ok(parsePublicationResult(result));
 invalid(parsePublicationResult({...result,binding:'reference.publish'}),'FORMAT');invalid(parsePublicationResult({...result,setId:source.setId}),'FIELDS');invalid(parsePublicationResult({...result,effectiveFrom:'2026-11-19T00:00:00.000Z'}),'INTERVAL');
});

test('canonical bundle SHA256 matches an independent Python UTF8 sorted-key vector',()=>{
 // Independently generated with Python json.dumps(sort_keys=True,ensure_ascii=False,separators=(',',':')).
 const b=ok(publication()),json=ok(serializeBundle(b,'json'));
 assert.equal(Buffer.byteLength(json.body.slice(0,-1)),1096);
 assert.equal(ok(publicationHash(b)),'2224297a074e18f16b90383d826a051887c5bb9aa5e21dfdb94ad739e726b45c');
 assert.equal(createHash('sha256').update(json.body.slice(0,-1),'utf8').digest('hex'),'2224297a074e18f16b90383d826a051887c5bb9aa5e21dfdb94ad739e726b45c');
});
