# SPDX-License-Identifier: Apache-2.0
"""Explicit qualification-only SQL032 splice; historical entrypoints stay inert."""
import hashlib
import json
from pathlib import Path
import re
import shutil

MIGRATION = '032_relation_candidate_validation.sql'
MIGRATION_SHA = '7837d2c9484c539330cb567cd550a4e19ee769360e0c9118d45837ded4f918b5'
THROUGH = tuple(f'{n:03d}' for n in range(18,25))
TABLES = "SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"
LEDGER = 'SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'
FUNCTIONS = "SELECT json_agg(jsonb_build_object('signature',p.oid::regprocedure::text,'owner',p.proowner::text,'acl',p.proacl::text,'definer',p.prosecdef,'config',p.proconfig,'volatility',p.provolatile,'body',md5(p.prosrc)) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','gc_authn','gc_authority');"
GUARDS = "SELECT jsonb_build_object('rls',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner,c.relacl::text) ORDER BY n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN('public','gc_authn','gc_authority')),'triggers',(SELECT jsonb_agg(jsonb_build_array(t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) ORDER BY t.tgrelid::regclass::text,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority')));"

def require(value, message):
    if not value: raise RuntimeError(message)

def sha(data): return hashlib.sha256(data).hexdigest()

def activate(h, through, root):
    require(through in THROUGH and getattr(h,'relation_candidate_mode',None) is None, 'Closed repaired profile required')
    require(sha((root/'packages/db/migrations'/MIGRATION).read_bytes()) == MIGRATION_SHA, 'Exact SQL032 source required')
    h.relation_candidate_mode = {'through':through,'applied':False,'completed':[], 'root':root}

def active(h):
    mode = getattr(h,'relation_candidate_mode',None)
    if mode is None: return False
    require(type(mode) is dict and set(mode)=={'through','applied','completed','root'} and mode['through'] in THROUGH
            and type(mode['applied']) is bool and type(mode['completed']) is list and isinstance(mode['root'],Path), 'Malformed repaired profile')
    return True

def names(h, original):
    if not active(h): return original
    require(type(original) is list and [n[:3] for n in original]==[f'{i:03d}' for i in range(1,len(original)+1)]
            and len(original)<=int(h.relation_candidate_mode['through']), 'Unexpected repaired prefix')
    if len(original)<18: return original
    require(h.relation_candidate_mode['applied'], 'SQL032 must apply before later stages')
    return [*original,MIGRATION]

def before(h, ledger, original):
    require(active(h), 'Repaired ledger check without profile')
    expected=names(h,original);root=h.relation_candidate_mode['root']
    require(type(ledger) is list and [r['name'] for r in ledger]==expected
            and all(r['checksum']==sha((root/'packages/db/migrations'/r['name']).read_bytes()) for r in ledger), 'Exact repaired predecessor ledger differs')
    return True

def after(h, prior, current, original, migration):
    before(h,prior,original);before(h,current,[*original,migration])
    require([r for r in current if r['name']!=migration]==prior
            and sum(r['name']==migration for r in current)==1, 'Repaired upgrade changed prior checksum/timestamp ledger')
    return True

def snapshot(h,tables):
    out={}
    for table in tables:
        require(re.fullmatch(r'(?:public|gc_authn|gc_authority)\.[a-z_]+',table), 'Unsafe fixed snapshot table')
        row=json.loads(h.sql(f"WITH rows AS MATERIALIZED(SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) value FROM {table} r) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM rows;"))
        require(type(row) is dict and set(row)=={'rows','sha256'} and type(row['rows']) is int and row['rows']>=0
                and isinstance(row['sha256'],str) and re.fullmatch('[a-f0-9]{64}',row['sha256']), 'Malformed canonical snapshot')
        out[table]=row
    return out

def apply(h, original):
    if not active(h): return
    mode=h.relation_candidate_mode;root=mode['root']
    require(not mode['applied'] and not mode['completed'] and len(original)==18
            and [n[:3] for n in original]==[f'{i:03d}' for i in range(1,19)], 'SQL032 splice must follow exact SQL018')
    h.phase='relation-candidate-predecessor'
    tables=json.loads(h.sql(TABLES));rows=snapshot(h,tables);prior=json.loads(h.sql(LEDGER))
    require([r['name'] for r in prior]==original and all(r['checksum']==sha((root/'packages/db/migrations'/r['name']).read_bytes()) for r in prior), 'Exact original SQL018 predecessor required')
    functions=json.loads(h.sql(FUNCTIONS));guards=h.sql(GUARDS)
    target=h.folder/'relation-candidate-target';target.mkdir()
    for name in [*original,MIGRATION]: shutil.copyfile(root/'packages/db/migrations'/name,target/name)
    require(sha((target/MIGRATION).read_bytes())==MIGRATION_SHA, 'SQL032 target changed')
    h.phase='relation-candidate-upgrade';result=h.migrate(target)
    require(re.findall(r'^Applied (.+)$',result.stdout,re.M)==[MIGRATION], 'Exactly SQL032 must apply at repaired splice')
    current=json.loads(h.sql(LEDGER));updated=json.loads(h.sql(FUNCTIONS))
    require([r['name'] for r in current]==[*original,MIGRATION] and current[:-1]==prior and current[-1]['checksum']==MIGRATION_SHA, 'Repaired ledger changed predecessor')
    require(len(updated)==len(functions), 'Function inventory changed')
    changed=[]
    for left,right in zip(functions,updated):
        if left!=right:
            require(left['signature']==right['signature']=='gc_relation_check_type(uuid,uuid)'
                    and {k:v for k,v in left.items() if k!='body'}=={k:v for k,v in right.items() if k!='body'}, 'Unexpected function/ACL change')
            changed.append(left['signature'])
    require(changed==['gc_relation_check_type(uuid,uuid)'], 'Exact changed checker required')
    require(json.loads(h.sql(TABLES))==tables and snapshot(h,tables)==rows and h.sql(GUARDS)==guards, 'Repair changed canonical/guard state')
    h.phase='relation-candidate-replay';require('Applied' not in h.migrate(target).stdout, 'Repair replay reapplied migration')
    require(json.loads(h.sql(LEDGER))==current and json.loads(h.sql(FUNCTIONS))==updated and h.sql(GUARDS)==guards
            and snapshot(h,tables)==rows and json.loads(h.sql(TABLES))==tables, 'Repair replay changed state')
    mode['applied']=True
    h.report['relationCandidateRepair']={'migration':MIGRATION,'sha256':MIGRATION_SHA,'priorLedger':prior,'ledger':current,
        'canonicalBaseline':rows,'functionBeforeSha256':sha(json.dumps(functions,sort_keys=True).encode()),
        'functionAfterSha256':sha(json.dumps(updated,sort_keys=True).encode()),'guardsSha256':sha(guards.encode()),'preservation':True,'replay':True}
    h.save()

def complete(h, original):
    if not active(h): return
    mode=h.relation_candidate_mode;stage=len(original)
    require(mode['applied'] and stage==18+len(mode['completed']), 'Missing, repeated or reordered repaired stage')
    ledger=json.loads(h.sql(LEDGER));before(h,ledger,original)
    require(ledger[-1]==h.report['relationCandidateRepair']['ledger'][-1], 'SQL032 checksum/timestamp changed')
    mode['completed'].append(stage)
    h.report.setdefault('repairedStages',[]).append({'prefix':f'{stage:03d}','migrations':names(h,original),
        'ledger':ledger,'nativeTests':dict(h.report['tests']),'result':'PASS'})
