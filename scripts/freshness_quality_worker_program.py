# SPDX-License-Identifier: Apache-2.0
# Native source executor qualification; launched only by the owned local helper.
import copy, hashlib, json, math, os, re, sys, time
from datetime import datetime, timezone
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


def micro(value):
    require(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z',value))
    v=datetime.fromisoformat(value)
    require(v.isoformat(timespec='microseconds').replace('+00:00','Z')==value)
    delta=v-datetime(1970,1,1,tzinfo=timezone.utc)
    return delta.days*86400000000+delta.seconds*1000000+delta.microseconds


def binding(age=3600,future=0):
    v={'maximumAgeSeconds':age,'maximumFutureSkewSeconds':future,'comparison':'latest-timestamptz',
       'clock':'source-statement-start','nullPolicy':'exclude','invalidTimestampPolicy':'fail'}
    return dict(v,freshnessHash=hashlib.sha256(json.dumps(dict(v,formatVersion=1,kind='freshness'),sort_keys=True,separators=(',',':')).encode()).hexdigest())


def measurement(value,expected,bound):
    fields={'formatVersion','kind','strategy','rowCount','nullCount','nonFiniteCount','unrepresentableCount','futureCount',
      'sourceObservedAt','latestObservedAt','ageMicroseconds','freshnessHash','observedStartedAt','observedFinishedAt',
      'elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes'}
    require(type(value) is dict and set(value)==fields and type(value['formatVersion']) is int and value['formatVersion']==1)
    require(value['kind']=='freshness' and value['strategy']=='exact-bounded-role-scope'
            and value['queryTemplate']=='postgresql-freshness-v1' and value['adapterVersion']=='1')
    for key,want in zip(('rowCount','nullCount','nonFiniteCount','unrepresentableCount','futureCount'),expected):
        require(type(value[key]) is int and value[key]==want)
    require(value['freshnessHash']==bound['freshnessHash'])
    at=micro(value['sourceObservedAt']); n=value['rowCount']-value['nullCount']
    represented=n-value['nonFiniteCount']-value['unrepresentableCount']
    if represented==0:require(value['latestObservedAt'] is None and value['ageMicroseconds'] is None)
    else:
        latest=micro(value['latestObservedAt'])
        require(type(value['ageMicroseconds']) is str and re.fullmatch(r'(?:0|-?[1-9][0-9]{0,17})',value['ageMicroseconds']))
        require(int(value['ageMicroseconds'])==at-latest)
        require((value['futureCount']>0)==(latest>at+bound['maximumFutureSkewSeconds']*1000000))
    require(type(value['elapsedMs']) is int and 0<=value['elapsedMs']<=30000)
    for key in ('observedStartedAt','observedFinishedAt'):
        require(type(value[key]) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',value[key]))
    started=micro(value['observedStartedAt'][:-1]+'000Z');finished=micro(value['observedFinishedAt'][:-1]+'000Z')
    require(0<=finished-started<=31000000 and abs(finished-started-value['elapsedMs']*1000)<=1000000)
    require(started-5000000<=at<=finished+5000000)
    require(type(value['sourceVersion']) is str and re.fullmatch(r'[0-9]{5,16}',value['sourceVersion']))
    require(type(value['estimatedCost']) in (int,float) and math.isfinite(value['estimatedCost']) and 0<=value['estimatedCost']<=1000000)
    require(type(value['estimatedBytes']) is int and 0<=value['estimatedBytes']<=67108864)
    verdict='NO_DATA' if n==0 else 'FAIL' if value['nonFiniteCount']+value['unrepresentableCount']+value['futureCount'] else 'PASS' if int(value['ageMicroseconds'])<=bound['maximumAgeSeconds']*1000000 else 'FAIL'
    return verdict


def main():
    config=load();matched=hashes(config['hashes'])
    if config['mode']=='probe':
        require(config['targets']=={});print(json.dumps({'ok':True,'hashes':matched},separators=(',',':')));return
    kinds={'fresh','stale','future','tolerated','infinity','outside','mixed','allinvalid','precision0','precision3','precision6',
           'offset','allnull','empty','naive','date','text','epoch','array','domain','rls','parent','child','many','edge'}
    require(config['mode'] in ('run','locked') and type(config['targets']) is dict)
    require(set(config['targets'])==({'fresh'} if config['mode']=='locked' else kinds))
    for kind,target in config['targets'].items():
        require(type(target) is dict and re.fullmatch(r'gc_fq_[a-f0-9]{32}_'+kind,target['tableName'])
                and target['columnName']=='payload' and target['schemaName']=='public')
    require(binding()['freshnessHash']=='b7cd429cfbc4669fdd7ddd36964234b7ec458affbe757af28de26030f063faf9')
    require(quality.validate_freshness_binding(binding())==binding())
    source={'connectorId':'postgresql','host':'source-postgres','port':5432,'database':'harbor','schema':'public','secretRef':'demo-postgres'}
    secret=resolve(os.environ['SOURCE_SECRETS_FILE'],'demo-postgres',config['tenantId'],'postgresql')
    require(secret['username']=='harbor_reader')
    budget={'maximumRows':100000,'maximumSeconds':30,'statementTimeoutMs':15000,'maximumEstimatedCost':1000000,'maximumEstimatedBytes':67108864}
    def request(target,age=3600,future=0):
        return {'formatVersion':1,'kind':'freshness','target':copy.deepcopy(target),'budget':dict(budget),'freshness':binding(age,future)}
    def run(value):return execute(source,secret,config['tenantId'],value)
    def refused(value,code):
        try:run(value)
        except ScanFailure as error:require(error.code==code)
        else:raise ValueError('expected refusal')
    if config['mode']=='locked':
        started=time.monotonic();refused(request(config['targets']['fresh']),'QUALITY_RESOURCE_LIMIT')
        elapsed=math.floor((time.monotonic()-started)*1000)
        require(1500<=elapsed<=6500 and hashes(config['hashes'])==matched)
        print(json.dumps({'ok':True,'hashes':matched,'checks':['actual_lock_timeout_refusal'],'elapsedMs':elapsed},separators=(',',':')));return
    expected=[
      ('fresh',(3,1,0,0,0),3600,0,'PASS'),('stale',(3,1,0,0,0),60,0,'FAIL'),
      ('future',(3,1,0,0,1),3600,0,'FAIL'),('tolerated',(2,1,0,0,0),3600,300,'PASS'),
      ('infinity',(3,1,2,0,0),3600,0,'FAIL'),('outside',(3,1,0,2,0),3600,0,'FAIL'),
      ('mixed',(4,1,1,1,0),3600,0,'FAIL'),('allinvalid',(5,1,2,2,0),3600,0,'FAIL'),
      ('precision0',(2,1,0,0,0),3600,0,'FAIL'),('precision3',(2,1,0,0,0),3600,0,'FAIL'),
      ('precision6',(2,1,0,0,0),3600,0,'FAIL'),('offset',(3,1,0,0,0),3600,0,'FAIL'),
      ('allnull',(5,5,0,0,0),3600,0,'NO_DATA'),('empty',(0,0,0,0,0),3600,0,'NO_DATA')]
    measurements=[]
    for kind,counts,age,future,verdict in expected:
        value=request(config['targets'][kind],age,future);result=run(value)
        require(measurement(result,counts,value['freshness'])==verdict);measurements.append(result)
    require([measurements[i]['latestObservedAt'] for i in (8,9,10,11)]==[
      '2020-02-29T08:00:00.000000Z','2020-02-29T08:00:00.123000Z',
      '2020-02-29T08:00:00.123456Z','2020-02-29T08:00:00.123456Z'])
    require(measurements[2]['latestObservedAt']=='9999-12-31T23:59:59.999999Z')
    require(-300000000 <= int(measurements[3]['ageMicroseconds']) < 0) # genuinely future, inside explicit tolerance
    require(len({v['sourceVersion'] for v in measurements})==1)
    plans=[];code=quality._estimates.__code__
    def observe(frame,event,arg):
        if frame.f_code is code and event=='return':
            require(len(plans)<1 and type(arg) is tuple and len(arg)==2);plans.append(arg)
    require(sys.getprofile() is None)
    try:
        sys.setprofile(observe);measured=run(request(config['targets']['fresh']))
    finally:sys.setprofile(None)
    require(len(plans)==1 and measured['estimatedCost']==plans[0][0] and measured['estimatedBytes']==plans[0][1])
    for field,index in [('maximumEstimatedCost',0),('maximumEstimatedBytes',1)]:
        cap=plans[0][index]/2 if index==0 else plans[0][index]//2;require(0<cap<plans[0][index])
        limited=request(config['targets']['fresh']);limited['budget'][field]=cap;refused(limited,'QUALITY_RESOURCE_LIMIT')
    for kind,lower in [('fresh',{'maximumRows':2}),('many',{})]:
        limited=request(config['targets'][kind]);limited['budget'].update(lower);refused(limited,'QUALITY_RESOURCE_LIMIT')
    target=config['targets']['fresh'];other=config['targets']['empty']
    stale={'databaseOid':str(1 if target['databaseOid']!='1' else 2),'schemaOid':str(1 if target['schemaOid']!='1' else 2),
      'relationOid':other['relationOid'],'attributeNumber':2,'schemaName':'quality_wrong_schema','tableName':other['tableName'],
      'columnName':'wrong_column','dataType':'timestamp without time zone'}
    for key,value in stale.items():
        changed=request(target);changed['target'][key]=value;refused(changed,'QUALITY_TARGET_STALE')
    for kind in ('naive','date','text','epoch','array','domain','rls','parent','child'):
        refused(request(config['targets'][kind]),'QUALITY_TARGET_UNSUPPORTED')
    with deadline(15):
        with _connection_parameters(source,secret,config['tenantId'],time.monotonic()+15) as params:
            with _Resources() as resources:
                with _blocked_alarm():
                    kwargs=dict(params);kwargs['connect_timeout']=5
                    conn=psycopg.connect(**kwargs,row_factory=dict_row);resources.own(conn.close)
                row=conn.execute("SELECT current_user AS name,current_setting('default_transaction_read_only') AS readonly,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
                require(row=={'name':'harbor_reader','readonly':'on','rolsuper':False,'rolbypassrls':False,'rolcreaterole':False,'rolcreatedb':False})
                conn.rollback();conn.execute('SET TRANSACTION READ WRITE')
                try:conn.execute(sql.SQL('UPDATE {} SET payload=NULL WHERE false').format(sql.Identifier('public',target['tableName'])))
                except psycopg.Error as error:require(error.sqlstate=='42501')
                else:raise ValueError('reader has write permission')
                finally:conn.rollback()
                # Exact SQL-template boundary controls have a fixed test clock;
                # they are separate from the fourteen unmodified execute() calls.
                edge=config['targets']['edge'];query,parameters=quality._freshness_aggregate(sql.Identifier('public',edge['tableName']),edge,budget,binding(60,300))
                template=query.as_string();require(template.count('pg_catalog.statement_timestamp()')==1)
                for clock,age,future in [('2026-01-01 00:01:00.000000+00','60000000',0),
                    ('2026-01-01 00:01:00.000001+00','60000001',0),
                    ('2025-12-31 23:55:00.000000+00','-300000000',0),
                    ('2025-12-31 23:54:59.999999+00','-300000001',1)]:
                    require(re.fullmatch(r'[0-9 -]+:[0-9:.]+\+00',clock))
                    controlled=template.replace('pg_catalog.statement_timestamp()',"'"+clock+"'::pg_catalog.timestamptz")
                    for zone in ('UTC','America/New_York','Asia/Dubai'):
                        conn.execute("SELECT set_config('TimeZone',%s,true),set_config('DateStyle','SQL, DMY',true)",(zone,))
                        result=conn.execute(controlled,parameters).fetchone()
                        require(result['row_count']==1 and result['null_count']==0 and result['non_finite_count']==0
                          and result['unrepresentable_count']==0 and result['future_count']==future
                          and result['age_microseconds']==age and result['latest_observed_at']=='2026-01-01T00:00:00.000000Z')
                conn.rollback()
    require(hashes(config['hashes'])==matched)
    print(json.dumps({'ok':True,'checks':[
      'latest_timestamp_recency_and_stale_oracle','future_values_cannot_mask_staleness',
      'explicit_future_tolerance','infinity_and_unrepresentable_fail_closed_counts',
      'empty_allnull_and_allinvalid_distinct','native_precision_zero_three_six',
      'equivalent_offsets_have_identical_max','exact_microsecond_template_boundary_oracle',
      'canonical_binding_hash_vector','lowered_row_bound_and_100001_refusal',
      'actual_plan_cost_and_bytes_refusal','all_eight_target_pins_refused_when_stale',
      'naive_date_text_epoch_array_domain_unsupported','rls_and_inheritance_unsupported',
      'native_reader_role_and_read_only_default','native_reader_dml_denied','closed_aggregates_without_row_examples'],
      'measurements':measurements,'plans':plans,'hashes':matched},separators=(',',':')))


try:main()
except BaseException:
    print(json.dumps({'ok':False,'code':'FRESHNESS_QUALITY_WORKER_QUALIFICATION_FAILED'},separators=(',',':')))
    sys.exit(1)
