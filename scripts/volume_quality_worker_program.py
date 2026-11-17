# SPDX-License-Identifier: Apache-2.0
# Native source executor qualification, launched only inside this run's helper.
import copy, hashlib, json, math, os, re, sys, time
from datetime import datetime
from pathlib import Path
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from governance_workers import quality
from governance_workers.quality import execute
from governance_workers.postgresql import ScanFailure, _connection_parameters
from governance_workers.secrets import resolve
from governance_workers.deadline import deadline
from governance_workers.postgres_targets import _Resources, _blocked_alarm


def require(value):
    if not value: raise ValueError('qualification refused')


def load():
    raw=sys.stdin.buffer.read(16385);require(len(raw)<=16384)
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result);result[k]=v
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('invalid scalar')))
    require(type(value) is dict and set(value)=={'mode','tenantId','targets','hashes'})
    require(value['tenantId']=='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    return value


def hashes(expected):
    require(type(expected) is dict and 1<=len(expected)<=64)
    result={}
    for path,digest in expected.items():
        require(re.fullmatch(r'python/(?:governance_workers/[a-z_]+\.py|pyproject\.toml|uv\.lock)',path))
        require(re.fullmatch(r'[a-f0-9]{64}',digest))
        actual=hashlib.sha256(Path('/worker',path.removeprefix('python/')).read_bytes()).hexdigest()
        require(actual==digest);result[path]=actual
    return result


def binding(minimum=0,maximum=5):
    v={'minimumRows':minimum,'maximumRows':maximum,'comparison':'row-count-inclusive','scope':'entire-table'}
    return dict(v,volumeHash=hashlib.sha256(json.dumps(dict(v,formatVersion=1,kind='volume'),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')).hexdigest())


def measurement(value,expected,bound):
    fields={'formatVersion','kind','strategy','rowCount','volumeHash','observedStartedAt','observedFinishedAt',
            'elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes'}
    require(type(value) is dict and set(value)==fields and type(value['formatVersion']) is int and value['formatVersion']==1)
    require(value['kind']=='volume' and value['strategy']=='exact-bounded-role-scope'
            and value['queryTemplate']=='postgresql-volume-v1' and value['adapterVersion']=='1')
    require(type(value['rowCount']) is int and value['rowCount']==expected and 0<=expected<=100000)
    require(value['volumeHash']==bound['volumeHash'])
    require(type(value['elapsedMs']) is int and 0<=value['elapsedMs']<=30000)
    for key in ('observedStartedAt','observedFinishedAt'):
        require(type(value[key]) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z',value[key]))
    elapsed=(datetime.fromisoformat(value['observedFinishedAt'])-datetime.fromisoformat(value['observedStartedAt'])).total_seconds()*1000
    require(0<=elapsed<=31000 and abs(elapsed-value['elapsedMs'])<=1000)
    require(type(value['sourceVersion']) is str and re.fullmatch(r'[0-9]{5,16}',value['sourceVersion']))
    require(type(value['estimatedCost']) in (int,float) and math.isfinite(value['estimatedCost']) and 0<=value['estimatedCost']<=1000000)
    require(type(value['estimatedBytes']) is int and 0<=value['estimatedBytes']<=67108864)
    # This gate's independent static oracle is not a canonical server verdict.
    return 'PASS' if bound['minimumRows']<=expected<=bound['maximumRows'] else 'FAIL'


def main():
    config=load();matched=hashes(config['hashes'])
    if config['mode']=='probe':
        require(config['targets']=={});print(json.dumps({'ok':True,'hashes':matched},separators=(',',':')));return
    kinds={'six','empty','limit','many','wide','rls','forced','parent','child','view','materialized','partition','leaf','columnonly','denied'}
    require(config['mode'] in ('run','locked') and type(config['targets']) is dict)
    require(set(config['targets'])==({'six'} if config['mode']=='locked' else kinds))
    for kind,target in config['targets'].items():
        require(type(target) is dict and set(target)=={'kind','databaseOid','schemaOid','relationOid','schemaName','tableName'}
                and re.fullmatch(r'gc_vq_[a-f0-9]{32}_'+kind,target['tableName'])
                and target['kind']=='table' and target['schemaName']=='public')
    vectors=[(0,5,'3b2199a5b4d34da6e2408b6fe7f6158434cad02517ee08b2c24ad06551a51219'),
             (0,0,'84f12349cdd0d6377677ea35694d2c074ed49c6f70e73fa085bd0c6b005219bd'),
             (100000,100000,'aaed04bc354ccdaf5ef948e5bd1a213331eb37059b433ea2dbf66759ee2eb0eb'),
             (6,6,'08d5c181809ded58cf68240b793f9e54f7a372b32b9fd0bf16cce1fcd993f421')]
    for minimum,maximum,want in vectors:
        require(binding(minimum,maximum)['volumeHash']==want)
        require(quality.validate_volume_binding(binding(minimum,maximum))==binding(minimum,maximum))
    source={'connectorId':'postgresql','host':'source-postgres','port':5432,'database':'harbor','schema':'public','secretRef':'demo-postgres'}
    secret=resolve(os.environ['SOURCE_SECRETS_FILE'],'demo-postgres',config['tenantId'],'postgresql')
    require(secret['username']=='harbor_reader')
    budget={'maximumRows':100000,'maximumSeconds':30,'statementTimeoutMs':15000,'maximumEstimatedCost':1000000,'maximumEstimatedBytes':67108864}
    def request(target,minimum=0,maximum=5):
        return {'formatVersion':1,'kind':'volume','target':copy.deepcopy(target),'budget':dict(budget),'volume':binding(minimum,maximum)}
    def run(value):return execute(source,secret,config['tenantId'],value)
    def refused(value,code):
        try:run(value)
        except ScanFailure as error:require(error.code==code)
        else:raise ValueError('expected refusal')
    if config['mode']=='locked':
        started=time.monotonic();refused(request(config['targets']['six']),'QUALITY_RESOURCE_LIMIT')
        elapsed=math.floor((time.monotonic()-started)*1000)
        require(1500<=elapsed<=6500 and hashes(config['hashes'])==matched)
        print(json.dumps({'ok':True,'hashes':matched,'checks':['actual_lock_timeout_refusal'],'elapsedMs':elapsed},separators=(',',':')));return
    expected=[('six',6,0,5,'FAIL'),('six',6,6,6,'PASS'),('six',6,7,7,'FAIL'),
              ('empty',0,0,0,'PASS'),('empty',0,1,1,'FAIL'),('limit',100000,100000,100000,'PASS'),
              ('wide',6,6,6,'PASS'),('six',6,0,100000,'PASS')]
    measurements=[]
    for index,(kind,rows,minimum,maximum,want) in enumerate(expected):
        value=request(config['targets'][kind],minimum,maximum)
        if index==7:value['budget']['maximumRows']=6
        result=run(value);require(measurement(result,rows,value['volume'])==want);measurements.append(result)
    require(len({v['sourceVersion'] for v in measurements})==1)
    for kind,lower in [('six',{'maximumRows':5}),('many',{})]:
        limited=request(config['targets'][kind],0,100000);limited['budget'].update(lower);refused(limited,'QUALITY_RESOURCE_LIMIT')
    plans=[];code=quality._estimates.__code__
    def observe(frame,event,arg):
        if frame.f_code is code and event=='return':
            require(len(plans)<1 and type(arg) is tuple and len(arg)==2);plans.append(arg)
    require(sys.getprofile() is None)
    try:
        sys.setprofile(observe);measured=run(request(config['targets']['six']))
    finally:sys.setprofile(None)
    require(len(plans)==1 and measured['estimatedCost']==plans[0][0] and measured['estimatedBytes']==plans[0][1])
    for field,index in [('maximumEstimatedCost',0),('maximumEstimatedBytes',1)]:
        cap=plans[0][index]/2 if index==0 else plans[0][index]//2;require(0<cap<plans[0][index])
        limited=request(config['targets']['six']);limited['budget'][field]=cap;refused(limited,'QUALITY_RESOURCE_LIMIT')
    target=config['targets']['six'];other=config['targets']['empty']
    stale={'databaseOid':str(1 if target['databaseOid']!='1' else 2),'schemaOid':str(1 if target['schemaOid']!='1' else 2),
           'relationOid':other['relationOid'],'schemaName':'quality_wrong_schema','tableName':other['tableName']}
    for key,value in stale.items():
        changed=request(target);changed['target'][key]=value;refused(changed,'QUALITY_TARGET_STALE')
    for kind in ('view','materialized','partition','leaf','parent','child','rls','forced'):
        refused(request(config['targets'][kind]),'QUALITY_TARGET_UNSUPPORTED')
    for kind in ('columnonly','denied'):refused(request(config['targets'][kind]),'SOURCE_SCOPE_DENIED')
    with deadline(15):
        with _connection_parameters(source,secret,config['tenantId'],time.monotonic()+15) as params:
            with _Resources() as resources:
                with _blocked_alarm():
                    kwargs=dict(params);kwargs['connect_timeout']=5
                    conn=psycopg.connect(**kwargs,row_factory=dict_row);resources.own(conn.close)
                row=conn.execute("SELECT current_user AS name,current_setting('default_transaction_read_only') AS readonly,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
                require(row=={'name':'harbor_reader','readonly':'on','rolsuper':False,'rolbypassrls':False,'rolcreaterole':False,'rolcreatedb':False})
                # PostgreSQL can permit COUNT/SELECT1 via a column grant; the
                # worker deliberately requires full table SELECT authority.
                conn.rollback()
                native=conn.execute(sql.SQL('SELECT pg_catalog.count(*) AS rows FROM ONLY {}').format(sql.Identifier('public',config['targets']['columnonly']['tableName']))).fetchone()
                require(native=={'rows':6})
                conn.rollback();conn.execute('SET TRANSACTION READ WRITE')
                try:conn.execute(sql.SQL('UPDATE {} SET amount=NULL WHERE false').format(sql.Identifier('public',target['tableName'])))
                except psycopg.Error as error:require(error.sqlstate=='42501')
                else:raise ValueError('reader has write permission')
                finally:conn.rollback()
    require(hashes(config['hashes'])==matched)
    print(json.dumps({'ok':True,'checks':[
      'six_rows_above_authored_maximum_is_exact_measurement','inclusive_threshold_oracles_and_static_hashes',
      'empty_table_is_exact_zero_not_no_data','exact_resource_cap_and_100001_refusal',
      'row_limit_independent_of_authored_bounds','whole_row_count_ignores_nulls_and_wide_values',
      'actual_plan_cost_and_bytes_refusal','all_five_source_table_pins_refused_when_stale',
      'views_materialized_partition_and_inheritance_refused','enabled_and_forced_rls_refused',
      'column_only_and_absent_table_grants_refused','native_reader_role_and_read_only_default',
      'native_reader_dml_denied','closed_aggregates_without_column_or_row_values'],
      'measurements':measurements,'plans':plans,'hashes':matched},separators=(',',':')))


if __name__=='__main__':
    try:main()
    except BaseException:
        sys.stderr.write('VOLUME_WORKER_PROGRAM_FAILED\n');raise SystemExit(1) from None
