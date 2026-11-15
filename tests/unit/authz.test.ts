// SPDX-License-Identifier: Apache-2.0
import {test} from 'node:test';import assert from 'node:assert/strict';import {canView,permits} from '../../packages/authz/src/index.ts';
const p={id:'user',name:'Synthetic',tenantId:'a',permissions:['catalog:read']};
test('tenant and explicit restricted metadata deny by default',()=>{
 assert.equal(canView(p,{tenantId:'b',visibility:'tenant'}),false);
 assert.equal(canView(p,{tenantId:'a',visibility:'restricted'}),false);
 assert.equal(canView(p,{tenantId:'a',visibility:'restricted',allowedIdentities:['user']}),true);
 assert.equal(permits(p,'sources:write'),false);
 assert.equal(canView({...p,permissions:[]},{tenantId:'a',visibility:'tenant'}),false);
});
