// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,session,inspect,counts,scalar} from '../fixtures/authority-authn-foundation.ts';

test('SQL036 protected issuance remains populated before application bridge installation',async t=>{
 const f=await fixture(t),before=await counts(f.owner),issued=await session(f);
 const descriptor=await inspect(f.api,issued.hash);
 assert.equal(descriptor.identity_id,f.identity);
 assert.equal(descriptor.content_authority,false);
 assert.equal(descriptor.authority_mode,'inactive');
 assert.equal((await counts(f.owner)).sessions,before.sessions+1);
 assert.equal((await scalar(f.owner,"SELECT to_regprocedure('public.gc_app_protected_session_v1(text,text)') IS NULL absent")).absent,true);
});
