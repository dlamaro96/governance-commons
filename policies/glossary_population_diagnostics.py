# SPDX-License-Identifier: Apache-2.0
"""Closed, source-bound failure diagnostics; never a qualification publisher."""
import importlib.util
import json
import re
from authentication_evidence import MIB, declarations, digest, exact, hashed, read_file, require, strict_json, timestamp

COMMAND='./dev test --suite glossary-population-upgrade'
PROFILE='isolated-glossary-population'
REPORT='.local/evidence/glossary-population-upgrade.json'
MARKER='GLOSSARY_POPULATION_DIAGNOSTIC_V1='
TIMING_MARKER='GLOSSARY_POPULATION_PHASES_V1='
TEST='tests/qualification/glossary-population.test.ts'
FIXED=('scripts/runtime-test-glossary-population-upgrade.py','packages/db/migrations/018_glossary_nominal_candidates.sql',TEST,
 'tests/fixtures/glossary-population-diagnostic.ts','policies/glossary_population_diagnostics.py','policies/authentication_evidence.py','policies/ci_evidence.py')
PHASES=frozenset(('admission','database-start','predecessor','pre013-preparation','checksum-refusal','upgrade','repeat-preparation',
 'approval-predecessor','approval-upgrade','approval-native-tests','glossary-predecessor','glossary-upgrade','glossary-native-tests',
 'scope-predecessor','relation-scope-upgrade','scope-native-tests','population-predecessor','glossary-population-upgrade','population-native-tests','cleanup'))
CATEGORIES=frozenset(('command_timeout','command_failed','suite_failed','invariant_failed','interrupted','unknown'))
OPERATIONS=frozenset(('fixture','population','target','policies','proposal','publication','assertions','replay'))
QUERIES=frozenset(('connect','begin','commit','rollback','settings','prepare','stage','finish','graph-source','graph-prepare','graph-complete','unclassified'))
STATES=frozenset(('08003','08006','22023','23503','23505','23514','25P02','40001','40P01','42501','42702','42703','42883','42P01','53000','53100','53200','53300','54000','55000','55P03','57014','57P01','P0001','P0002'))
CODES=frozenset(('UNCLASSIFIED','ERR_ASSERTION','RELATION_RETRY','RELATION_PROFILE_LIMIT','RELATION_INVALID','RELATION_CARDINALITY','RELATION_CYCLE','GLOSSARY_STORAGE_INVALID','GLOSSARY_UNAVAILABLE','GLOSSARY_INPUT_INVALID','GLOSSARY_CONFLICT','GLOSSARY_FORBIDDEN','GLOSSARY_LIMIT','GLOSSARY_PUBLICATION_INVALID'))

def predecessor(root):
    spec=importlib.util.spec_from_file_location('population_diagnostic_scope',root/'scripts/runtime-test-relation-scope-upgrade.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def source_inventory(root):
    names={row['path'] for row in predecessor(root).sources()}|set(FIXED)
    pending=[name for name in names if name.endswith(('.ts','.tsx'))]
    while pending:
        name=pending.pop()
        for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''',read_file(root,name,16*MIB).decode()):
            candidate=(root/name).parent/relative
            if not candidate.suffix:candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate/'index.ts'
            cursor=root
            for part in candidate.relative_to(root).parts:
                cursor=cursor/part
                require(not cursor.is_symlink())
            require(candidate.resolve().is_relative_to(root.resolve()))
            child=str(candidate.resolve().relative_to(root.resolve()))
            read_file(root,child,16*MIB)
            if child not in names:names.add(child);pending.append(child)
    require(len(names)<=4096)
    require(all(len(name)<=512 and re.fullmatch(r'[A-Za-z0-9_.\-/]+',name) for name in names))
    return [{'path':name,'sha256':digest(read_file(root,name,16*MIB))} for name in sorted(names)]

def suite_files(root,phase):
    module=predecessor(root)
    if phase=='population-native-tests':return [*module.TESTS,TEST]
    if phase=='scope-native-tests':return module.TESTS
    if phase=='glossary-native-tests':return module.base.TESTS
    if phase=='approval-native-tests':return module.base.base.TESTS
    return []

def integer(value,maximum=3600000):require(type(value) is int and 0<=value<=maximum)

def timing(raw):
    require(type(raw) is str and len(raw.encode())<=16384)
    value=strict_json(raw.encode());exact(value,('phase','elapsedMs','queryCount','omittedQueries','code','sqlstate','queries'))
    require(value['phase'] in OPERATIONS and value['code'] in CODES and (value['sqlstate'] is None or value['sqlstate'] in STATES))
    integer(value['elapsedMs']);integer(value['queryCount'],1000000);integer(value['omittedQueries'],1000000)
    rows=value['queries'];require(type(rows) is list and len(rows)<=64 and len(rows)+value['omittedQueries']==value['queryCount'])
    previous=0
    for row in rows:
        exact(row,('phase','query','startedMs','elapsedMs','outcome','sqlstate'))
        require(row['phase'] in OPERATIONS and row['query'] in QUERIES and row['outcome'] in ('fulfilled','rejected'))
        require(row['sqlstate'] is None or row['outcome']=='rejected' and row['sqlstate'] in STATES)
        integer(row['startedMs']);integer(row['elapsedMs'])
        require(previous<=row['startedMs'] and row['startedMs']+row['elapsedMs']<=value['elapsedMs']+1);previous=row['startedMs']
    return value

def tap(root,phase,text):
    expected=[row for name in suite_files(root,phase) for row in declarations(root,name)]
    require(len(expected)<=256 and len({row['title'] for row in expected})==len(expected))
    by_title={row['title']:row for row in expected};seen=set();numbers=set();records=[];timings=[];unmapped=False
    matches=list(re.finditer(r'^(ok|not ok) ([1-9][0-9]*) - ([^\r\n]*)$',text,re.M))
    for i,match in enumerate(matches):
        title=re.sub(r' # (?:SKIP|TODO)(?: .*)?$','',match[3]);number=int(match[2])
        if title not in by_title or title in seen or number in numbers:
            unmapped=True;continue
        seen.add(title);numbers.add(number);where=by_title[title]
        chunk=text[match.end():matches[i+1].start() if i+1<len(matches) else len(text)]
        status='skipped' if title!=match[3] else 'passed' if match[1]=='ok' else 'cancelled' if re.search(r'failureType: [\'\"]?cancelledByParent',chunk) else 'failed'
        records.append({'file':where['file'],'line':where['line'],'status':status})
        if status=='failed' and TIMING_MARKER in chunk:
            require(where['file']==TEST and phase=='population-native-tests')
            error=re.search(r'^([ ]+)error: \|-?\s*\n((?:\1[ ]+[^\n]*\n)+)',chunk,re.M)
            require(error is not None and 'Population qualification failed; diagnostic' in error[2])
            found=re.findall(r'^ +'+TIMING_MARKER+r'(.*)$',error[2],re.M);require(len(found)==1)
            timings.append({'file':where['file'],'line':where['line'],**timing(found[0])})
    records.extend({'file':r['file'],'line':r['line'],'status':'not_observed'} for r in expected if r['title'] not in seen)
    return records,timings,unmapped

def _safe_report(root,value,commit):
    require(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version']==1 and value.get('result')=='FAIL')
    require(type(commit) is str and re.fullmatch('[a-f0-9]{40}',commit) and value.get('commit')==commit)
    require(value.get('command')==COMMAND and value.get('profile')==PROFILE)
    require(0<=(timestamp(value['recorded_at'])-timestamp(value['started_at'])).total_seconds()<=3600)
    sources=source_inventory(root);require(value['diagnostic_sources']==sources)
    folder=value['evidence_directory'];require(type(folder) is str and re.fullmatch(r'\.local/evidence/source-connectors-upgrade-[0-9]{8}T[0-9]{6}-[0-9a-f]{12}',folder))
    failure=value['failure_diagnostic'];exact(failure,('phase','category','commandLog','elapsedMs'))
    phase,category=failure['phase'],failure['category'];integer(failure['elapsedMs'])
    require(phase in PHASES and phase==value['failed_phase'] and category in CATEGORIES)
    logs=value['private_logs'];require(type(logs) is list and len(logs)<=2048)
    selected=None;total=0;seen=set();ordinals=set();digests=[]
    for row in logs:
        exact(row,('path','sha256'));name=row['path'];require(type(name) is str and name.startswith(folder+'/'))
        match=re.fullmatch(r'([0-9]{3,4})-([a-z0-9_-]+)\.log',name[len(folder)+1:]);require(match is not None and match[2] in PHASES)
        ordinal=int(match[1]);require(1<=ordinal<=2048 and ordinal not in ordinals and name not in seen);ordinals.add(ordinal);seen.add(name)
        data=read_file(root,name,4*MIB+2048);total+=len(data);require(total<=100*MIB and digest(data)==hashed(row['sha256']))
        text=data.decode();header=re.match(r'phase=([a-z0-9_-]+)\nexit=(-?[0-9]{1,3})\n',text);require(header is not None and header[1]==match[2])
        if row==failure['commandLog']:require(match[2]==phase);selected=(text,int(header[2]),row['sha256'])
        digests.append({'ordinal':ordinal,'phase':match[2],'sha256':row['sha256']})
    if failure['commandLog'] is None:
        require(category in ('unknown','invariant_failed','interrupted'));text,exit_code,log_hash='',None,None
    else:
        exact(failure['commandLog'],('path','sha256'));require(selected is not None);text,exit_code,log_hash=selected
        require(re.findall(r'^'+MARKER+r'([a-z_]+)$',text,re.M)==[category] and text.endswith(MARKER+category+'\n'))
        if category in ('command_failed','suite_failed'):require(exit_code!=0)
        if category=='suite_failed':require(phase.endswith('-native-tests'))
    tests,timings,unmapped=tap(root,phase,text)
    flags=value.get('cleanup',{});require(type(flags) is dict)
    return {'schema_version':1,'purpose':'FAILURE_DIAGNOSTIC_ONLY','outcome':'NOT_PASSED','commit':commit,'command':COMMAND,'profile':PROFILE,
      'started_at':value['started_at'],'recorded_at':value['recorded_at'],'failed_phase':phase,'category':category,'elapsed_ms':failure['elapsedMs'],
      'exit_code':exit_code,'command_log_sha256':log_hash,'command_log_available':selected is not None,'tests':tests,'population_timings':timings,
      'unmapped_test_output':unmapped,'source_files':sources,'source_inventory_sha256':digest(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()),
      'log_digests':digests,'cleanup':{name:flags.get(name) is True for name in ('ownedRemoved','resourceInventoryPreserved')},
      'limitations':['Failure diagnostics only; no successful qualification is inferred.','Only fixed operation/query categories, finite error codes, exact static test coordinates and bounded timings are exported. Missing output leaves cause unknown.','Raw messages, SQL, parameters, result rows and private paths remain private. Existing product and suite timeouts are unchanged.']}

def safe_report(root,value,commit):
    try:return _safe_report(root,value,commit)
    except (OSError,ValueError,TypeError,KeyError,IndexError,OverflowError):return None

def load_report(root,commit):
    try:return safe_report(root,strict_json(read_file(root,REPORT,4*MIB)),commit)
    except (OSError,ValueError,TypeError,KeyError):return None
