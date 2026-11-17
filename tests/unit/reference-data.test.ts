// SPDX-License-Identifier: Apache-2.0
// Pure unit tests; database and browser qualification run separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {LIMITS,type ApprovalPayload,type Audience,type Labels,type PublishedBundle,type ReferenceValue,type Result} from '../../packages/domain/src/reference-data-contracts.ts';
import {parseRelease,parseProposal,parseProposalJSON,parseApprovalPayload,parsePublishedBundle,preparePublication,publicationHash,approvalDigestPreimage,proposalDigest,selectEffective,serializeBundle,parsePublicationResult} from '../../packages/domain/src/reference-data.ts';

const owner='10000000-0000-4000-8000-000000000001',reviewer='10000000-0000-4000-8000-000000000002';
const setId='20000000-0000-4000-8000-000000000001',requestId='30000000-0000-4000-8000-000000000001';
const audience:Audience={visibility:'tenant',allowedIdentityIds:[]};
const stamp=(day:number)=>`2026-11-${String(day).padStart(2,'0')}T00:00:00.000Z`;
const labels=(label='State'):Labels=>({en:{label,description:'Business state, exact "code".\nSecond line.'},ar:{label:'حالة',description:'وصف الحالة باللغة العربية'}});
const value=(code='NEW'):ReferenceValue=>({code,labels:labels(),ownerId:owner,status:'active',validFrom:null,validUntil:null});
function rawRelease(){return {formatVersion:1,kind:'reference-code-list',labels:labels(),ownerId:owner,status:'active',activation:{kind:'on-publication'},validUntil:null,values:[value()]};}
function good<T>(result:Result<T>):T{assert.equal(result.ok,true,result.ok?'':JSON.stringify(result.issues));if(!result.ok)throw new Error('Expected valid fixture.');return result.value;}
function bad(result:Result<unknown>,code?:string,path?:string){assert.equal(result.ok,false);if(result.ok)throw new Error('Expected rejection.');if(code)assert.equal(result.issues[0].code,code);if(path)assert.equal(result.issues[0].path,path);}
function payload(expectedVersion=0,release:unknown=rawRelease()):ApprovalPayload{return good(parseApprovalPayload({formatVersion:1,kind:'reference-publication',setId,expectedVersion,audience,release}));}
function publish(day=1,previous:PublishedBundle|null=null,release:unknown=rawRelease()):PublishedBundle{return good(preparePublication({payload:payload(previous?.version??0,release),publishedAt:stamp(day),previous,previousAudience:previous?audience:null}));}
function proposal(){return {id:requestId,setId,expectedVersion:0,audience,release:rawRelease(),workflow:{id:'reference_review',version:1,definitionHash:'a'.repeat(64)},assignments:{review:reviewer},expiresAt:stamp(28)};}

/** Independent RFC4180 fixture reader: no production export helper or header
 * constants are used to reconstruct expected values. This is not an import API. */
function readCsv(text:string):string[][] {
 const rows:string[][]=[];let row:string[]=[],cell='',quoted=false,closed=false;
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(quoted){if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;continue;}
  if(c==='"'){assert.equal(cell,'');assert.equal(closed,false);quoted=true;}
  else if(c===','){row.push(cell);cell='';closed=false;}
  else if(c==='\r'){assert.equal(text[++i],'\n');row.push(cell);rows.push(row);row=[];cell='';closed=false;}
  else{assert.equal(closed,false);assert.notEqual(c,'\n');cell+=c;}
 }
 assert.equal(quoted,false);assert.equal(cell,'');assert.deepEqual(row,[]);return rows;
}
function fromCsv(text:string):PublishedBundle {
 const [header,...rows]=readCsv(text);
 assert.deepEqual(header,['format_version','kind','set_id','version','set_labels_json','set_owner_id','set_status','published_at','effective_from','set_valid_until','code','value_labels_json','value_owner_id','value_status','value_valid_from','value_valid_until']);
 assert.ok(rows.length>0);const head=rows[0].slice(0,10);
 const values=rows.map(row=>{assert.equal(row.length,16);assert.deepEqual(row.slice(0,10),head);return {code:row[10],labels:JSON.parse(row[11]),ownerId:row[12],status:row[13],validFrom:row[14]||null,validUntil:row[15]||null};});
 return {formatVersion:Number(head[0]),kind:head[1],setId:head[2],version:Number(head[3]),labels:JSON.parse(head[4]),ownerId:head[5],status:head[6],publishedAt:head[7],effectiveFrom:head[8],validUntil:head[9]||null,values} as PublishedBundle;
}

test('normalizes EN/AR text and exact code ordering without numeric/case coercion',()=>{
 const source={...rawRelease(),labels:{en:{label:'  Cafe\u0301  ',description:' Details '},ar:{label:' حالة ',description:' وصف '}},values:['2','10','001','a','A'].map(value)};
 const parsed=good(parseRelease(source));assert.equal(parsed.labels.en.label,'Café');assert.equal(parsed.labels.ar.label,'حالة');
 assert.deepEqual(parsed.values.map(row=>row.code),['001','10','2','A','a']);assert.equal(source.labels.en.label,'  Cafe\u0301  ');
 assert.ok(Object.isFrozen(parsed)&&Object.isFrozen(parsed.values)&&Object.isFrozen(parsed.values[0].labels.ar));
 source.values[0]={...source.values[0],code:'CHANGED'};assert.equal(parsed.values[3].code,'A');
 bad(parseRelease({...rawRelease(),values:[value('A'),value('A')]}),'DUPLICATE','/values/1/code');
 bad(parseRelease({...rawRelease(),values:[value(' A')]}),'FORMAT','/values/0/code');
});

test('text bounds apply to original UTF-16 before trim/NFC and again after normalization',()=>{
 const withText=(label:string,description='Description')=>({...rawRelease(),labels:{en:{label,description},ar:labels().ar}});
 assert.equal(good(parseRelease(withText(' '.repeat(239)+'X'))).labels.en.label,'X');
 bad(parseRelease(withText(' '.repeat(240)+'X')),'FORMAT','/labels/en/label');
 assert.equal(good(parseRelease(withText('State',' '.repeat(2047)+'X'))).labels.en.description,'X');
 bad(parseRelease(withText('State',' '.repeat(2048)+'X')),'FORMAT','/labels/en/description');
 bad(parseRelease(withText('e\u0301'.repeat(121))),'FORMAT','/labels/en/label');
 assert.equal(good(parseRelease(withText('😀'.repeat(120)))).labels.en.label,'😀'.repeat(120));
 bad(parseRelease(withText('😀'.repeat(121))),'FORMAT','/labels/en/label');
 bad(parseRelease(withText('\u0344'.repeat(121))),'FORMAT','/labels/en/label');
 bad(parseRelease(withText(' '.repeat(240))),'FORMAT','/labels/en/label');
});

test('trim cannot hide label controls; multiline descriptions explicitly permit tab/CR/LF only',()=>{
 const withText=(label:string,description='Description')=>({...rawRelease(),labels:{en:{label,description},ar:labels().ar}});
 for(const label of ['\nState','State\r','\tState\t','\vState\f'])bad(parseRelease(withText(label)),'FORMAT','/labels/en/label');
 const parsed=good(parseRelease(withText('State','\t\nFirst line\r\nSecond\tline\n')));
 assert.equal(parsed.labels.en.description,'First line\r\nSecond\tline');
 for(const description of ['\vDescription','Description\f','\u0085Description'])bad(parseRelease(withText('State',description)),'FORMAT','/labels/en/description');
});

test('rejects accessor/toJSON/cycle/proxy inputs without invoking user behavior',()=>{
 let invoked=0;const getter={...rawRelease()};Object.defineProperty(getter,'labels',{enumerable:true,get(){invoked++;return labels();}});
 bad(parseRelease(getter),'INVALID_JSON');assert.equal(invoked,0);
 bad(parseRelease({...rawRelease(),toJSON(){invoked++;return rawRelease();}}),'INVALID_JSON');assert.equal(invoked,0);
 const cyclic:Record<string,unknown>=rawRelease();cyclic.labels=cyclic;bad(parseRelease(cyclic),'INVALID_JSON');
 const proxy=new Proxy(rawRelease(),{getPrototypeOf(){invoked++;throw new Error('trap');},ownKeys(){invoked++;throw new Error('trap');}});
 bad(parseRelease(proxy),'INVALID_JSON');assert.equal(invoked,0);
 const withSymbol={...rawRelease(),[Symbol('hidden')]:true};bad(parseRelease(withSymbol),'INVALID_JSON');
 const nonenumerable={...rawRelease()};Object.defineProperty(nonenumerable,'labels',{value:labels(),enumerable:false});bad(parseRelease(nonenumerable),'INVALID_JSON');
});

test('rejects malformed JSON data, sparse arrays, unsafe properties and Unicode',()=>{
 bad(parseRelease({...rawRelease(),formatVersion:-0}),'INVALID_JSON');
 bad(parseRelease({...rawRelease(),formatVersion:Infinity}),'INVALID_JSON');
 bad(parseRelease({...rawRelease(),labels:new Date()}),'INVALID_JSON');
 const sparse=Array(1);bad(parseRelease({...rawRelease(),values:sparse}),'INVALID_JSON');
 const extra=[value()];Object.defineProperty(extra,'x',{value:true,enumerable:true});bad(parseRelease({...rawRelease(),values:extra}),'INVALID_JSON');
 bad(parseRelease({...rawRelease(),labels:{en:{label:'bad\ud800',description:'Description'},ar:labels().ar}}),'FORMAT');
 bad(parseRelease({...rawRelease(),labels:{en:{label:'bad\u0000',description:'Description'},ar:labels().ar}}),'FORMAT');
 bad(parseRelease({...rawRelease(),labels:Object.assign(Object.create(null),{'constructor':'bad'})}),'INVALID_JSON');
});

test('raw JSON refuses duplicate escaped fields and reserved-key escapes',()=>{
 const raw=JSON.stringify(proposal());assert.equal(good(parseProposalJSON(raw,owner)).setId,setId);
 bad(parseProposalJSON(raw.replace('"expectedVersion":0','"expectedVersion":0,"expected\\u0056ersion":1'),owner),'INVALID_JSON');
 bad(parseProposalJSON(raw.replace('"expectedVersion":0','"expectedVersion":0,"\\u005f_proto__":{}'),owner),'INVALID_JSON');
 bad(parseProposalJSON(raw+' trailing',owner),'INVALID_JSON');
 bad(parseProposalJSON('"'+'ح'.repeat(200000)+'"',owner),'LIMIT');
});

test('enforces finite byte, string, node, depth and value-count budgets',()=>{
 bad(parseRelease({...rawRelease(),values:Array.from({length:257},(_,i)=>value(String(i)))}),'LIMIT');
 bad(parseRelease({...rawRelease(),labels:{en:{label:'a'.repeat(LIMITS.stringUtf16+1),description:'Text'},ar:labels().ar}}),'LIMIT');
 const wide=Array.from({length:256},()=>Array.from({length:256},()=>null));bad(parseRelease({...rawRelease(),values:wide}),'LIMIT');
 let deep:unknown=null;for(let i=0;i<20;i++)deep={child:deep};bad(parseRelease({...rawRelease(),labels:deep}),'LIMIT');
 const huge=Array.from({length:80},(_,i)=>({...value(String(i)),labels:{en:{label:'State',description:'ح'.repeat(2048)},ar:{label:'حالة',description:'ح'.repeat(2048)}}}));
 bad(parseRelease({...rawRelease(),values:huge}),'LIMIT');
});

test('proposal uses exact closed fields and complete distinct nonrequester principal union',()=>{
 const parsed=good(parseProposal(proposal(),owner));assert.equal(parsed.workflow.id,'reference_review');
 bad(parseProposal({...proposal(),other:true},owner),'FIELDS');
 bad(parseProposal({...proposal(),assignments:{review:owner}},owner),'FORMAT');
 bad(parseProposal({...proposal(),assignments:{first:reviewer,second:reviewer}},owner),'FORMAT');
 bad(parseProposal({...proposal(),audience:{visibility:'restricted',allowedIdentityIds:[owner]}},owner),'FORMAT');
 const restricted=good(parseProposal({...proposal(),audience:{visibility:'restricted',allowedIdentityIds:[reviewer,owner]}},owner));assert.deepEqual(restricted.audience.allowedIdentityIds,[owner,reviewer]);
 const ids=Array.from({length:63},(_,i)=>`40000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`);
 const ownersAtLimit={...rawRelease(),values:ids.map((id,i)=>({...value(String(i)),ownerId:id}))};
 good(parseRelease(ownersAtLimit)); // 63 value owners plus set owner already fill 64 slots
 bad(parseProposal({...proposal(),release:ownersAtLimit},owner),'LIMIT'); // independent reviewer is the 65th
});

test('approval digest uses the exact complete envelope and an independent UTF-8 golden vector',()=>{
 const input=proposal(),preimage=good(approvalDigestPreimage(input,owner));
 assert.deepEqual(preimage,{id:requestId,binding:'reference.publish',payload:payload(),workflow:input.workflow,assignments:Object.assign(Object.create(null),input.assignments),expiresAt:input.expiresAt});
 // Independently computed with Python hashlib + sorted compact JSON, ensure_ascii=False.
 assert.equal(good(proposalDigest(input,owner)),'2d8c8d19013e8f1a408a2af61a46e03cf17b6cc086d65b4295e9b57cbfae33d3');
 const normalized={...input,release:{...input.release,labels:{...input.release.labels,en:{...input.release.labels.en,label:' State '}}}};
 assert.equal(good(proposalDigest(normalized,owner)),good(proposalDigest(input,owner)));
 assert.ok(Object.isFrozen(preimage)&&Object.isFrozen(preimage.payload.release)&&Object.isFrozen(preimage.assignments));
});

test('every proposal-identity component changes the digest; callers cannot inject binding',()=>{
 const input=proposal(),baseline=good(proposalDigest(input,owner));
 const changes=[
  {...input,id:'30000000-0000-4000-8000-000000000002'},
  {...input,setId:'20000000-0000-4000-8000-000000000002'},
  {...input,expectedVersion:1},
  {...input,audience:{visibility:'restricted',allowedIdentityIds:[owner,reviewer]}},
  {...input,release:{...input.release,status:'deprecated'}},
  {...input,workflow:{...input.workflow,id:'second_review'}},
  {...input,workflow:{...input.workflow,version:2}},
  {...input,workflow:{...input.workflow,definitionHash:'b'.repeat(64)}},
  {...input,assignments:{review:'10000000-0000-4000-8000-000000000003'}},
  {...input,assignments:{different:reviewer}},
  {...input,expiresAt:stamp(27)},
 ];
 for(const changed of changes)assert.notEqual(good(proposalDigest(changed,owner)),baseline);
 bad(proposalDigest({...input,binding:'glossary.publish'},owner),'FIELDS');
});

test('publication resolves immediate time and refuses backdating, elapsed schedules and changed heads',()=>{
 const first=publish();assert.equal(first.effectiveFrom,stamp(1));assert.equal(first.publishedAt,stamp(1));assert.equal(first.version,1);
 const scheduled={...rawRelease(),activation:{kind:'at',at:stamp(10)}};
 const second=publish(2,first,scheduled);assert.equal(second.version,2);assert.equal(second.effectiveFrom,stamp(10));
 bad(preparePublication({payload:payload(1,scheduled),publishedAt:stamp(10),previous:first,previousAudience:audience}),'CONFLICT');
 bad(preparePublication({payload:payload(2),publishedAt:stamp(3),previous:second,previousAudience:audience}),'CONFLICT');
 bad(preparePublication({payload:payload(0),publishedAt:stamp(3),previous:first,previousAudience:audience}),'CONFLICT');
 bad(parsePublishedBundle({...first,effectiveFrom:'2026-10-31T23:59:59.999Z'}),'INTERVAL');
 bad(preparePublication({payload:payload(1),publishedAt:stamp(1),previous:first,previousAudience:audience}),'CONFLICT');
 bad(parseRelease({...rawRelease(),activation:{kind:'at',at:'2026-02-30T00:00:00.000Z'}}),'FORMAT','/activation/at');
});

test('published audience and set identity cannot silently change through a successor',()=>{
 const first=publish();const restricted={visibility:'restricted',allowedIdentityIds:[owner,reviewer]};
 bad(preparePublication({payload:{...payload(1),audience:restricted},publishedAt:stamp(2),previous:first,previousAudience:audience}),'CONFLICT','/audience');
 bad(preparePublication({payload:{...payload(1),setId:reviewer},publishedAt:stamp(2),previous:first,previousAudience:audience}),'CONFLICT');
 bad(preparePublication({payload:payload(0),publishedAt:stamp(2),previous:null,previousAudience:audience}),'CONFLICT');
});

test('historical answers stay fixed after a future successor is published',()=>{
 const first=publish();const before=good(selectEffective([first],stamp(2),stamp(2)));
 const second=publish(3,first,{...rawRelease(),labels:labels('Next'),activation:{kind:'at',at:stamp(10)}});
 const after=good(selectEffective([first,second],stamp(2),stamp(20)));assert.deepEqual(after,before);
 const scheduled=good(selectEffective([first,second],stamp(4),stamp(20)));assert.equal(scheduled.version,1);assert.equal(scheduled.effectiveUntil,stamp(10));
 const effective=good(selectEffective([first,second],stamp(10),stamp(20)));assert.equal(effective.version,2);assert.equal(effective.phase,'EFFECTIVE');
 assert.equal(good(selectEffective([first,second],'2026-11-09T23:59:59.999Z',stamp(20))).version,1);
 assert.equal(good(selectEffective([first,second],undefined,stamp(20))).version,2);
});

test('release and code intervals are half-open; expired successors never revive earlier versions',()=>{
 const first=publish();const second=publish(2,first,{...rawRelease(),validUntil:stamp(8),values:[{...value('EARLY'),validUntil:stamp(5)},{...value('LATE'),validFrom:stamp(5)}]});
 assert.deepEqual(good(selectEffective([first,second],stamp(4),stamp(20))).values.map(row=>row.code),['EARLY']);
 assert.deepEqual(good(selectEffective([first,second],stamp(5),stamp(20))).values.map(row=>row.code),['LATE']);
 const expired=good(selectEffective([first,second],stamp(8),stamp(20)));assert.equal(expired.phase,'EXPIRED');assert.equal(expired.version,2);assert.deepEqual(expired.values,[]);
 bad(parseRelease({...rawRelease(),values:[{...value(),validFrom:stamp(5),validUntil:stamp(5)}]}),'INTERVAL');
 bad(preparePublication({payload:payload(0,{...rawRelease(),validUntil:stamp(1)}),publishedAt:stamp(1),previous:null,previousAudience:null}),'INTERVAL');
 const deprecated=publish(9,second,{...rawRelease(),status:'deprecated'});assert.equal(good(selectEffective([first,second,deprecated],stamp(9),stamp(20))).phase,'DEPRECATED');
});

test('scheduled first publication stays not-effective and exact version remains downloadable',()=>{
 const scheduled=publish(1,null,{...rawRelease(),activation:{kind:'at',at:stamp(10)}});
 const selection=good(selectEffective([scheduled],stamp(5),stamp(20)));assert.equal(selection.phase,'NOT_EFFECTIVE');assert.equal(selection.version,null);assert.deepEqual(selection.values,[]);
 assert.equal(JSON.parse(good(serializeBundle(scheduled,'json')).body).values[0].code,'NEW');
 assert.equal(good(selectEffective([scheduled],stamp(10),stamp(20))).version,1);
});

test('history selection refuses gaps, mixed sets, reversed starts, future query/time and oversized histories',()=>{
 const first=publish(),second=publish(2,first);
 bad(selectEffective([second],stamp(5),stamp(20)),'CONFLICT');
 bad(selectEffective([first,{...second,setId:owner}],stamp(5),stamp(20)),'CONFLICT');
 bad(selectEffective([first,{...second,effectiveFrom:stamp(1),publishedAt:stamp(1)}],stamp(5),stamp(20)),'CONFLICT');
 bad(selectEffective([first,second],stamp(21),stamp(20)),'FORMAT');
 bad(selectEffective([first,second],stamp(1),stamp(1)),'CONFLICT');
 bad(selectEffective(Array.from({length:129},()=>first),stamp(5),stamp(20)),'LIMIT');
 let invoked=0;const input=[first];Object.defineProperty(input,'0',{enumerable:true,get(){invoked++;return first;}});bad(selectEffective(input,stamp(5),stamp(20)),'INVALID_JSON');assert.equal(invoked,0);
});

test('stored bundles refuse silent normalization; hash and JSON download preserve exact approved values',()=>{
 const first=publish(1,null,{...rawRelease(),values:[value('a'),value('A')]});
 bad(parsePublishedBundle({...first,values:[...first.values].reverse()}),'NON_CANONICAL');
 bad(parsePublishedBundle({...first,labels:{...first.labels,en:{...first.labels.en,label:' State '}}}),'NON_CANONICAL');
 const json=good(serializeBundle(first,'json'));assert.deepEqual(JSON.parse(json.body),first);
 assert.equal(good(publicationHash(first)),createHash('sha256').update(json.body.slice(0,-1)).digest('hex'));
 const reordered=Object.fromEntries(Object.entries(first).reverse());assert.equal(good(publicationHash(reordered)),good(publicationHash(first)));
 assert.equal(good(serializeBundle(reordered,'json')).etag,json.etag);
 assert.notEqual(good(publicationHash({...first,labels:labels('Different')})),good(publicationHash(first)));
});

test('CSV is lossless for Unicode, quotes, line breaks, leading zeros and nullable intervals',()=>{
 const first=publish(1,null,{...rawRelease(),labels:labels('=SUM(A1:A2)'),values:[{...value('001'),labels:labels('Comma, "quote"'),status:'deprecated',validUntil:stamp(8)},{...value('A'),validFrom:stamp(5)}]});
 const csv=good(serializeBundle(first,'csv')),json=good(serializeBundle(first,'json'));
 assert.deepEqual(fromCsv(csv.body),first);assert.equal(csv.byteLength,Buffer.byteLength(csv.body,'utf8'));
 const rows=readCsv(csv.body);assert.equal(rows[1][10],'001');assert.equal(rows[1][4][0],'{');assert.equal(rows[1][11][0],'{');
 assert.notEqual(csv.etag,json.etag);assert.equal(csv.etag,good(serializeBundle(first,'csv')).etag);
 assert.ok(csv.body.endsWith('\r\n'));assert.equal(good(selectEffective([first],stamp(9),stamp(20))).values.length,1);
 assert.equal(fromCsv(csv.body).values.length,2); // full immutable download, not an effective list
});

test('complete maximum-size downloads include all 256 values and reject unrecognized format',()=>{
 const first=publish(1,null,{...rawRelease(),values:Array.from({length:256},(_,i)=>value(String(i).padStart(3,'0')))});
 const csv=good(serializeBundle(first,'csv')),json=good(serializeBundle(first,'json'));
 assert.equal(readCsv(csv.body).length,257);assert.deepEqual(fromCsv(csv.body),first);assert.deepEqual(JSON.parse(json.body),first);
 assert.ok(csv.byteLength<LIMITS.downloadBytes);bad(serializeBundle(first,'xlsx'),'FORMAT');
});

test('publication receipts reject unknown fields, bindings, malformed pins and backdating',()=>{
 const receipt={binding:'reference.publish',setId,version:1,publicationHash:'a'.repeat(64),publishedAt:stamp(1),effectiveFrom:stamp(2)};
 assert.deepEqual(good(parsePublicationResult(receipt)),receipt);
 bad(parsePublicationResult({...receipt,extra:true}),'FIELDS');
 bad(parsePublicationResult({...receipt,binding:'glossary.publish'}),'FORMAT','/binding');
 bad(parsePublicationResult({...receipt,publicationHash:'A'.repeat(64)}),'FORMAT','/publicationHash');
 bad(parsePublicationResult({...receipt,version:0}),'FORMAT','/version');
 bad(parsePublicationResult({...receipt,effectiveFrom:stamp(1),publishedAt:stamp(2)}),'INTERVAL','/effectiveFrom');
 let invoked=false;const getter={...receipt};Object.defineProperty(getter,'publicationHash',{enumerable:true,get(){invoked=true;return receipt.publicationHash;}});
 bad(parsePublicationResult(getter),'INVALID_JSON');assert.equal(invoked,false);
});

test('fresh proposals reserve a successor version while the final immutable version remains valid',()=>{
 const lastExpected=LIMITS.version-1;
 assert.equal(payload(lastExpected).expectedVersion,lastExpected);
 bad(parseApprovalPayload({...payload(),expectedVersion:LIMITS.version}),'LIMIT','/expectedVersion');
 bad(parseProposal({...proposal(),expectedVersion:LIMITS.version},owner),'LIMIT','/expectedVersion');
 const previous={...publish(),version:lastExpected};
 const final=good(preparePublication({payload:payload(lastExpected),publishedAt:stamp(2),previous,previousAudience:audience}));
 assert.equal(final.version,LIMITS.version);assert.deepEqual(good(parsePublishedBundle(final)),final);
 assert.equal(JSON.parse(good(serializeBundle(final,'json')).body).version,LIMITS.version);
});
