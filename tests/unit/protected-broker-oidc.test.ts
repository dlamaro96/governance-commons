// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {CompactSign,SignJWT,exportJWK,generateKeyPair} from 'jose';
import {createOidcClient,validateBrokerOidcConfig} from '../../packages/authn/src/oidc.ts';
import type {BrokerOidcConfig} from '../../packages/authn/src/contracts.ts';
import type {AttemptExchange} from '../../packages/authority/src/authentication.ts';
import type {UTC,UUID} from '../../packages/authority/src/types.ts';
import {sha256} from '../../packages/authn/src/transport.ts';

const config:BrokerOidcConfig={publicOrigin:'http://localhost:4314',environment:'isolated-test',issuer:'http://localhost:4315/realms/governance',clientId:'governance-protected-web',redirectUri:'http://localhost:4314/authn/callback',authorizationEndpoint:'http://localhost:4315/realms/governance/protocol/openid-connect/auth',tokenEndpoint:'http://localhost:4315/realms/governance/protocol/openid-connect/token',jwksUri:'http://localhost:4315/realms/governance/protocol/openid-connect/certs'};
const clock=Date.parse('2026-11-16T12:00:00.000Z'),seconds=clock/1000,nonce='n'.repeat(43),state='s'.repeat(43),verifier='v'.repeat(43);
const attempt:AttemptExchange={formatVersion:1,attemptId:'10000000-0000-0000-0000-000000000001' as UUID,issuerId:'10000000-0000-0000-0000-000000000002' as UUID,issuer:config.issuer,clientId:config.clientId,redirectUri:config.redirectUri,nonceHash:sha256(nonce),verifier,expiresAt:new Date(clock+300_000).toISOString() as UTC};
const pair=await generateKeyPair('RS256',{modulusLength:2048});
const publicKey={...await exportJWK(pair.publicKey),kid:'test-rsa',alg:'RS256',use:'sig'};
const payload=()=>({iss:config.issuer,sub:'synthetic-subject',aud:config.clientId,iat:seconds,exp:seconds+300,auth_time:seconds,nonce});
const metadata=()=>({issuer:config.issuer,authorization_endpoint:config.authorizationEndpoint,token_endpoint:config.tokenEndpoint,jwks_uri:config.jwksUri,id_token_signing_alg_values_supported:['RS256']});
const json=(value:unknown)=>new Response(JSON.stringify(value),{status:200,headers:{'content-type':'application/json'}});
async function signed(changes:Record<string,unknown>={},header:Record<string,unknown>={}):Promise<string>{return new SignJWT({...payload(),...changes}).setProtectedHeader({alg:'RS256',kid:publicKey.kid,typ:'JWT',...header}).sign(pair.privateKey);}
function fixture(options:{token?:string;keys?:unknown;metadata?:unknown;fetchOverride?:(url:string,init:RequestInit)=>Response|Promise<Response>|undefined;config?:BrokerOidcConfig}={}){
 const requests:{url:string;init:RequestInit}[]=[];const client=createOidcClient(options.config??config,{now:()=>clock,fetch:(async(input,init={})=>{
  const url=String(input);requests.push({url,init});const override=options.fetchOverride?.(url,init);if(override!==undefined)return override;
  if(url.endsWith('/.well-known/openid-configuration'))return json(options.metadata??metadata());
  if(url.endsWith('/certs'))return json(options.keys??{keys:[publicKey]});
  if(url.endsWith('/token'))return json({id_token:options.token,access_token:'discarded',refresh_token:'discarded',token_type:'Bearer'});
  throw new Error('Unexpected unit transport endpoint');
 }) as typeof fetch});return {client,requests};
}
const loginRejected=(error:unknown)=>!!error&&typeof error==='object'&&'code'in error&&error.code==='AUTHN_LOGIN_INVALID';

test('protected OIDC verifies actual RS256 signature and exact claim/token bindings, with fresh login parameters',async()=>{
 const token=await signed(),{client,requests}=fixture({token});await client.initialize();
 const result=await client.exchangeAndVerify(attempt,'synthetic-code');
 assert.deepEqual(result,{issuer:config.issuer,subject:'synthetic-subject',audience:config.clientId,nonceHash:sha256(nonce),idTokenHash:sha256(token),authenticatedAt:new Date(clock).toISOString(),tokenIssuedAt:new Date(clock).toISOString(),tokenExpiresAt:new Date(clock+300_000).toISOString()});
 const url=new URL(client.authorizationUrl({state,nonce,verifier}));assert.equal(url.searchParams.get('max_age'),'0');assert.deepEqual(JSON.parse(url.searchParams.get('claims')!),{id_token:{auth_time:{essential:true}}});
 assert.equal(url.searchParams.get('response_type'),'code');assert.equal(url.searchParams.get('code_challenge_method'),'S256');assert.equal(url.searchParams.get('code_challenge'),Buffer.from(sha256(verifier),'hex').toString('base64url'));
 const sent=requests.find(x=>x.url===config.tokenEndpoint)!;assert.equal(sent.init.redirect,'manual');assert.equal(sent.init.credentials,'omit');assert.deepEqual(Object.fromEntries(new URLSearchParams(String(sent.init.body))),{grant_type:'authorization_code',code:'synthetic-code',client_id:config.clientId,redirect_uri:config.redirectUri,code_verifier:verifier});
 assert.equal(requests.filter(x=>x.url===config.jwksUri).length,1);assert.equal(Object.hasOwn(result,'access_token'),false);
});

test('protected OIDC refuses signed issuer, audience, azp, nonce and authentication freshness violations',async()=>{
 const cases:Record<string,unknown>[]=[{iss:'https://other.invalid'},{aud:'other'},{aud:[config.clientId,'other']},{azp:'other'},{aud:[config.clientId,config.clientId],azp:config.clientId},{aud:Array.from({length:9},(_,i)=>i?`client${i}`:config.clientId),azp:config.clientId},{nonce:'x'.repeat(43)},{auth_time:seconds-31},{auth_time:seconds+1},{iat:seconds+1},{iat:seconds-1},{exp:seconds},{exp:seconds-1},{auth_time:String(seconds)},{iat:seconds+0.5},{exp:Number.MAX_SAFE_INTEGER}];
 for(const claims of cases){const {client}=fixture({token:await signed(claims)});await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);}
 const {client}=fixture({token:await signed({auth_time:seconds-30,aud:[config.clientId,'other'],azp:config.clientId})});await client.initialize();assert.equal((await client.exchangeAndVerify(attempt,'code')).audience,config.clientId);
});

test('protected OIDC requires every claim without fallback and rejects invalid dates and subject types',async()=>{
 for(const field of ['iss','sub','aud','exp','iat','nonce','auth_time']){const claims=payload() as Record<string,unknown>;delete claims[field];const token=await new SignJWT(claims).setProtectedHeader({alg:'RS256',kid:publicKey.kid}).sign(pair.privateKey);const {client}=fixture({token});await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);}
 for(const changes of [{sub:[]},{sub:'x'.repeat(1025)},{auth_time:-1},{exp:253402300800}]){const {client}=fixture({token:await signed(changes)});await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);}
});

test('protected OIDC rejects forged signatures, unknown keys, remote key headers and non-RS256 algorithms',async()=>{
 const other=await generateKeyPair('RS256');const forged=await new SignJWT(payload()).setProtectedHeader({alg:'RS256',kid:publicKey.kid}).sign(other.privateKey);
 const tokens=[forged,await signed({}, {kid:'unknown'}),await signed({}, {jku:'https://attacker.invalid/keys'}),await signed({}, {jwk:publicKey}),await signed({}, {x5u:'https://attacker.invalid/cert'}),await signed({}, {typ:'at+jwt'})];
 tokens.push(await new SignJWT(payload()).setProtectedHeader({alg:'HS256',kid:publicKey.kid}).sign(new Uint8Array(32)));
 for(const token of tokens){const {client,requests}=fixture({token});await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);assert.equal(requests.filter(x=>x.url===config.jwksUri).length,1);assert.equal(requests.some(x=>x.url.includes('attacker')),false);}
});

test('protected OIDC admits exact duplicate-free raw JWT JSON before signature verification',async()=>{
 const duplicated=`${JSON.stringify(payload()).slice(0,-1)},"auth_time":${seconds}}`;
 const token=await new CompactSign(Buffer.from(duplicated)).setProtectedHeader({alg:'RS256',kid:publicKey.kid}).sign(pair.privateKey);
 const {client}=fixture({token});await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);
 const oversized=fixture({token:await signed({extra:'x'.repeat(8192)})});await oversized.client.initialize();await assert.rejects(oversized.client.exchangeAndVerify(attempt,'code'),loginRejected);
});

test('protected OIDC validates metadata exact endpoints and initialization gates authorization and exchange',async()=>{
 const {client}=fixture({token:await signed()});assert.throws(()=>client.authorizationUrl({state,nonce,verifier}),loginRejected);await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);
 for(const field of ['issuer','authorization_endpoint','token_endpoint','jwks_uri']){const bad=fixture({metadata:{...metadata(),[field]:'https://other.invalid/path'}});await assert.rejects(bad.client.initialize(),loginRejected);}
 const bad=fixture({metadata:{...metadata(),id_token_signing_alg_values_supported:['HS256']}});await assert.rejects(bad.client.initialize(),loginRejected);
});

test('protected OIDC rejects private, duplicate, oversized and weak signing keys while allowing unrelated public encryption keys',async()=>{
 const weak={...publicKey,n:Buffer.alloc(128,255).toString('base64url')};
 for(const keys of [[{...publicKey,d:'private'}],[publicKey,{...publicKey}],[weak],Array.from({length:33},(_,i)=>({...publicKey,kid:`key${i}`})),[{...publicKey,n:'A'.repeat(684)}]]){const {client}=fixture({keys:{keys}});await assert.rejects(client.initialize(),loginRejected);}
 const {client}=fixture({token:await signed(),keys:{keys:[publicKey,{kty:'EC',kid:'unrelated-encryption',use:'enc',alg:'ECDH-ES',crv:'P-256',x:'bounded-public-x',y:'bounded-public-y'}]}});await client.initialize();assert.equal((await client.exchangeAndVerify(attempt,'code')).subject,'synthetic-subject');
});

test('protected OIDC streamed byte limits apply without or despite misleading Content-Length and cancel overflow',async()=>{
 let cancelled=false;const {client}=fixture({fetchOverride:url=>url.endsWith('openid-configuration')?new Response(new ReadableStream<Uint8Array>({start(controller){controller.enqueue(Buffer.alloc(32769,32));},cancel(){cancelled=true;}}),{headers:{'content-type':'application/json','content-length':'1'}}):undefined});
 await assert.rejects(client.initialize(),loginRejected);assert.equal(cancelled,true);
 const token=fixture({token:await signed(),fetchOverride:url=>url.endsWith('/token')?new Response(' '.repeat(65537),{headers:{'content-type':'application/json'}}):undefined});await token.client.initialize();await assert.rejects(token.client.exchangeAndVerify(attempt,'code'),loginRejected);
 const compressed=fixture({fetchOverride:url=>url.endsWith('openid-configuration')?new Response(' '.repeat(32769),{headers:{'content-type':'application/json','content-encoding':'gzip'}}):undefined});await assert.rejects(compressed.client.initialize(),loginRejected);
});

test('protected OIDC refuses redirects, malformed JSON, invalid UTF8 and semantic JSON depth/node overflows',async()=>{
 const responses=[()=>new Response(null,{status:302,headers:{location:'https://other.invalid'}}),()=>new Response('{"issuer":1,"issuer":2}',{headers:{'content-type':'application/json'}}),()=>new Response(new Uint8Array([0xc3,0x28]),{headers:{'content-type':'application/json'}}),()=>json({nested:[[[[[[[[[1]]]]]]]]]}),()=>json({nodes:Array.from({length:2049},()=>1)}),()=>new Response('{}',{headers:{'content-type':'text/html'}})];
 for(const response of responses){const {client,requests}=fixture({fetchOverride:url=>url.endsWith('openid-configuration')?response():undefined});await assert.rejects(client.initialize(),loginRejected);assert.equal(requests.length,1);}
});

test('protected OIDC validates consumed tuple before any token request and honors original abort signal',async()=>{
 const {client,requests}=fixture({token:await signed()});await client.initialize();
 for(const changes of [{issuer:'https://other.invalid'},{clientId:'other'},{redirectUri:'http://localhost:4314/other'}])await assert.rejects(client.exchangeAndVerify({...attempt,...changes},'code'),loginRejected);
 const controller=new AbortController();controller.abort();await assert.rejects(client.exchangeAndVerify(attempt,'code',{signal:controller.signal}),loginRejected);assert.equal(requests.length,2);
});

test('protected OIDC aliases only fixed local transport URLs, never accepted issuer or production TLS',async()=>{
 const aliases=Object.fromEntries([`${config.issuer}/.well-known/openid-configuration`,config.tokenEndpoint,config.jwksUri].map(url=>[url,`http://keycloak:8080${new URL(url).pathname}`]));
 const {client,requests}=fixture({config:{...config,transportAliases:aliases},token:await signed()});await client.initialize();const result=await client.exchangeAndVerify(attempt,'code');assert.equal(result.issuer,config.issuer);assert.ok(requests.every(x=>x.url.startsWith('http://keycloak:8080/')));
 assert.throws(()=>validateBrokerOidcConfig({...config,transportAliases:{[config.tokenEndpoint]:'http://attacker.invalid/token'}}));
 assert.throws(()=>validateBrokerOidcConfig({...config,environment:'production'}));
 assert.throws(()=>validateBrokerOidcConfig({...config,redirectUri:'http://localhost:4314/elsewhere'}));
 assert.throws(()=>validateBrokerOidcConfig({...config,tokenEndpoint:'http://localhost:4315/other/token'}));
 for(const issuer of ['http://localhost:0/realms/governance','http://localhost:4315/realms/%zz','https://id_bad.example/realms/governance','https://[2001:db8::1]/realms/governance'])assert.throws(()=>validateBrokerOidcConfig({...config,issuer}));
 const secure={...config,environment:'production' as const,publicOrigin:'https://app.example',redirectUri:'https://app.example/authn/callback',issuer:'https://id.example/realms/governance',authorizationEndpoint:'https://id.example/realms/governance/auth',tokenEndpoint:'https://id.example/realms/governance/token',jwksUri:'https://id.example/realms/governance/certs'};assert.equal(validateBrokerOidcConfig(secure).environment,'production');assert.throws(()=>validateBrokerOidcConfig({...secure,transportAliases:aliases}));
});

test('protected OIDC coalesces startup and shares a bounded in-memory signing-key fetch across consumers',async()=>{
 const {client,requests}=fixture({token:await signed()});await Promise.all([client.initialize(),client.initialize(),client.initialize()]);await Promise.all(Array.from({length:8},()=>client.exchangeAndVerify(attempt,'code')));assert.equal(requests.filter(x=>x.url.endsWith('openid-configuration')).length,1);assert.equal(requests.filter(x=>x.url===config.jwksUri).length,1);
});

test('protected OIDC cancels rejected response bodies and aborts a stalled token stream on the caller deadline',async()=>{
 let rejectedCancelled=false;const rejected=fixture({fetchOverride:url=>url.endsWith('openid-configuration')?new Response(new ReadableStream<Uint8Array>({cancel(){rejectedCancelled=true;}}),{status:302,headers:{location:'https://other.invalid'}}):undefined});await assert.rejects(rejected.client.initialize(),loginRejected);assert.equal(rejectedCancelled,true);
 let streamCancelled=false;const controller=new AbortController();
 const {client}=fixture({fetchOverride:url=>url.endsWith('/token')?new Response(new ReadableStream<Uint8Array>({start(stream){stream.enqueue(Buffer.from('{'));queueMicrotask(()=>controller.abort());},cancel(){streamCancelled=true;}}),{headers:{'content-type':'application/json'}}):undefined});
 await client.initialize();const started=Date.now();await assert.rejects(client.exchangeAndVerify(attempt,'code',{signal:controller.signal}),loginRejected);assert.ok(Date.now()-started<1000);assert.equal(streamCancelled,true);
});
