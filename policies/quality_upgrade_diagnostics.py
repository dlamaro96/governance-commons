# SPDX-License-Identifier: Apache-2.0
"""Quality-upgrade failure coordinates only; never publishes qualification."""
import importlib.util
import json
import re
from authentication_evidence import MIB, declarations, digest, exact, hashed, read_file, require, strict_json, timestamp
from glossary_population_diagnostics import CATEGORIES, MARKER, PHASES as POPULATION_PHASES, suite_files as predecessor_suite_files

COMMAND='./dev test --suite quality-upgrade'
PROFILE='isolated-quality-execution'
REPORT='.local/evidence/quality-upgrade.json'
TEST='tests/qualification/quality.test.ts'
REPAIRED_COMMAND='./dev test --suite quality-repaired-upgrade'
REPAIRED_PROFILE='isolated-governance-repaired-sql019'
REPAIRED_REPORT='.local/evidence/quality-repaired-upgrade.json'
PHASES=POPULATION_PHASES|{'quality-predecessor-source','quality-predecessor','quality-upgrade','quality-native-tests'}
REPAIRED_PHASES=PHASES|{'relation-candidate-predecessor','relation-candidate-upgrade','relation-candidate-replay'}
COUNTERS=('tests','suites','pass','fail','cancelled','skipped','todo')
CODE_CLASSES={'ERR_ASSERTION':'ASSERTION_FAILURE','57014':'DATABASE_DEADLINE','42883':'DATABASE_FUNCTION_UNAVAILABLE',
 '23503':'DATABASE_CONSTRAINT','23505':'DATABASE_CONSTRAINT','23514':'DATABASE_CONSTRAINT','42501':'DATABASE_PERMISSION',
 '40001':'DATABASE_RETRY','40P01':'DATABASE_RETRY','53000':'DATABASE_RESOURCE','53100':'DATABASE_RESOURCE',
 '53200':'DATABASE_RESOURCE','53300':'DATABASE_RESOURCE','54000':'DATABASE_RESOURCE','ERR_TEST_FAILURE':'TEST_PROCESS_FAILURE'}


def integer(value,maximum=3600000):require(type(value) is int and 0<=value<=maximum)


def source_inventory(root):
    spec=importlib.util.spec_from_file_location('quality_diagnostic_scope',root/'scripts/runtime-test-quality-upgrade.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return checked_inventory(root,module.sources())


def repaired_wrapper(root):
    spec=importlib.util.spec_from_file_location('quality_repaired_diagnostic_scope',root/'scripts/runtime-test-governance-repaired-upgrade.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module,module.load('019')


def repaired_source_inventory(root):
    module,selected=repaired_wrapper(root)
    return checked_inventory(root,module.sources(selected))


def checked_inventory(root,rows):
    require(type(rows) is list and 0<len(rows)<=4096)
    names=set()
    for row in rows:
        exact(row,('path','sha256'));hashed(row['sha256'])
        require(type(row['path']) is str and row['path'] not in names)
        require(digest(read_file(root,row['path'],16*MIB))==row['sha256']);names.add(row['path'])
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
    require(0<len(names)<=4096)
    require(all(len(name)<=512 and re.fullmatch(r'[A-Za-z0-9_.\-/]+',name) for name in names))
    return [{'path':name,'sha256':digest(read_file(root,name,16*MIB))} for name in sorted(names)]


def suite_files(root,phase):
    return [TEST] if phase=='quality-native-tests' else predecessor_suite_files(root,phase)


def tap(root,phase,text):
    expected=[row for name in suite_files(root,phase) for row in declarations(root,name)]
    require(len(expected)<=256 and len({row['title'] for row in expected})==len(expected))
    by_title={row['title']:row for row in expected};seen=set();numbers=set();records=[];unmapped=False
    matches=list(re.finditer(r'^(ok|not ok) ([1-9][0-9]{0,5}) - ([^\r\n]*)$',text,re.M))
    for index,match in enumerate(matches):
        title=re.sub(r' # (?:SKIP|TODO)(?: .*)?$','',match[3],flags=re.I);number=int(match[2])
        if title not in by_title or title in seen or number in numbers:
            unmapped=True;continue
        seen.add(title);numbers.add(number);where=by_title[title]
        block=text[match.end():matches[index+1].start() if index+1<len(matches) else len(text)]
        status=('todo' if re.search(r' # TODO(?: .*)?$',match[3],re.I) else 'skipped') if title!=match[3] else 'passed' if match[1]=='ok' else 'cancelled' if re.search(r'^  failureType: [\'\"]?cancelledByParent[\'\"]?$',block,re.M) else 'failed'
        # Only a single top-level TAP diagnostic code is classified. Indented
        # error/expected/stack content cannot manufacture a metadata field.
        fields=re.findall(r'^  code: (.*)$',block,re.M)
        parsed=re.fullmatch(r"(?:'([A-Z0-9_]+)'|\"([A-Z0-9_]+)\"|([A-Z0-9_]+))",fields[0]) if len(fields)==1 else None
        code=next((part for part in parsed.groups() if part),'') if parsed else ''
        classification=CODE_CLASSES.get(code,'UNKNOWN') if status=='failed' else None
        records.append({'file':where['file'],'line':where['line'],'status':status,'classification':classification})
    records.extend({'file':row['file'],'line':row['line'],'status':'not_observed','classification':None} for row in expected if row['title'] not in seen)
    counts={};valid=len(re.findall(r'^TAP version 13$',text,re.M))==1
    for name in COUNTERS:
        fields=re.findall(r'^# '+name+r'(?: (.*))?$',text,re.M)
        valid_field=len(fields)==1 and re.fullmatch(r'[0-9]{1,6}',fields[0]) is not None
        valid=valid and valid_field
        counts[name]=int(fields[0]) if valid_field else None
    plan=re.findall(r'^1\.\.(.*)$',text,re.M)
    valid=valid and len(plan)==1 and re.fullmatch(r'[0-9]{1,6}',plan[0]) is not None and all(type(value) is int and value<=100000 for value in counts.values())
    if valid:
        valid=(counts['suites']==0 and int(plan[0])==counts['tests']==len(matches)
          and sum(counts[name] for name in ('pass','fail','cancelled','skipped','todo'))==counts['tests']
          and [int(match[2]) for match in matches]==list(range(1,len(matches)+1)))
    if valid and not unmapped:
        valid=all(counts[counter]==sum(row['status']==status for row in records) for counter,status in
          (('pass','passed'),('fail','failed'),('cancelled','cancelled'),('skipped','skipped'),('todo','todo')))
    state='UNAVAILABLE_OR_INVALID' if not valid else 'COMPLETE' if expected and len(seen)==len(expected) and not unmapped else 'PARTIAL_OR_UNMAPPED'
    return {'expected_tests':len(expected) if expected else None,'tap_counts':counts if valid else None,
      'counts_state':state,'tests':records,'unmapped_test_output':unmapped}


def repaired_native_context(root,value,phase,sources):
    require(value.get('qualification')=='EXPLICIT_REPAIRED_CHAIN' and value.get('historicalOutcome')=='HISTORICAL_NOT_EXECUTED' and value.get('through')=='019')
    module,selected=repaired_wrapper(root);plan=module.native_plan(selected)
    require(value.get('repairedNativePlan')==plan)
    rows=value.get('repairedNativeSuites');require(type(rows) is list and len(rows)<=len(plan))
    pins=module.allowed_pins(selected);selected_effective=None
    for i,row in enumerate(rows):
        require(type(row) is dict and row.get('phase')==plan[i]['phase'] and row.get('files')==plan[i]['files'] and row.get('expected')==plan[i]['expected'])
        require(row.get('result') in ('RUNNING','PASS','FAIL') and row.get('checkoutSources')==sources)
        effective=row.get('effectiveSources');require(type(effective) is list and len(effective)==len(sources))
        for declared,actual in zip(sources,effective):
            exact(actual,('path','sha256'));hashed(actual['sha256'])
            require(actual['path']==declared['path'] and (actual['sha256']==declared['sha256'] or actual['sha256'] in pins.get(actual['path'],set())))
        if row['phase']==phase:
            require(i==len(rows)-1);selected_effective=effective
        else:require(row['result']=='PASS')
    if phase in {row['phase'] for row in plan} and selected_effective is None:
        require(len(rows)<len(plan) and plan[len(rows)]['phase']==phase)
    return selected_effective


def _safe_report(root,value,commit,repaired=False):
    require(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version']==1 and value.get('result')=='FAIL')
    require(type(commit) is str and re.fullmatch('[a-f0-9]{40}',commit) and value.get('commit')==commit)
    command,profile,phases=(REPAIRED_COMMAND,REPAIRED_PROFILE,REPAIRED_PHASES) if repaired else (COMMAND,PROFILE,PHASES)
    require(value.get('command')==command and value.get('profile')==profile and value.get('quality_diagnostic_capture') is None)
    require(0<=(timestamp(value['recorded_at'])-timestamp(value['started_at'])).total_seconds()<=3600)
    sources=repaired_source_inventory(root) if repaired else source_inventory(root)
    require(value['repairedCheckoutSources' if repaired else 'quality_diagnostic_sources']==sources)
    folder=value['evidence_directory'];require(type(folder) is str and re.fullmatch(r'\.local/evidence/source-connectors-upgrade-[0-9]{8}T[0-9]{6}-[0-9a-f]{12}',folder))
    failure=value['failure_diagnostic'];exact(failure,('phase','category','commandLog','elapsedMs'))
    phase,category=failure['phase'],failure['category'];integer(failure['elapsedMs'])
    require(phase in phases and phase==value['failed_phase'] and category in CATEGORIES)
    effective=repaired_native_context(root,value,phase,sources) if repaired else None
    maximum_logs=4096 if repaired else 2048
    logs=value['private_logs'];require(type(logs) is list and len(logs)<=maximum_logs)
    seen=set();ordinals=set();selected=None
    for row in logs:
        exact(row,('path','sha256'));name=row['path'];require(type(name) is str and name.startswith(folder+'/'))
        match=re.fullmatch(r'([0-9]{3,4})-([a-z0-9_-]+)\.log',name[len(folder)+1:]);require(match is not None and match[2] in phases)
        ordinal=int(match[1]);require(1<=ordinal<=maximum_logs and ordinal not in ordinals and name not in seen)
        ordinals.add(ordinal);seen.add(name);hashed(row['sha256'])
        if row==failure['commandLog']:
            require(match[2]==phase)
            data=read_file(root,name,4*MIB+2048);require(digest(data)==row['sha256'])
            text=data.decode();header=re.match(r'phase=([a-z0-9_-]+)\nexit=(-?[0-9]{1,3})\n',text)
            require(header is not None and header[1]==phase and -128<=int(header[2])<=255)
            selected=(text,int(header[2]),row['sha256'])
    if failure['commandLog'] is None:
        require(category in ('unknown','invariant_failed','interrupted'));text,exit_code,log_hash='',None,None
    else:
        exact(failure['commandLog'],('path','sha256'));require(selected is not None);text,exit_code,log_hash=selected
        require(re.findall(r'^'+MARKER+r'([a-z_]+)$',text,re.M)==[category] and text.endswith(MARKER+category+'\n'))
        if category in ('command_failed','suite_failed'):require(exit_code!=0)
        if category=='suite_failed':require(phase.endswith('-native-tests'))
    projection=tap(root,phase,text)
    if repaired and projection['tap_counts'] is not None:
        require(effective is not None)
        stage=value['repairedNativeSuites'][-1]
        require(stage.get('tests')==projection['tap_counts'] and type(stage.get('exitStatus')) is int and stage['exitStatus']==exit_code)
    flags=value.get('cleanup',{});require(type(flags) is dict)
    return {'schema_version':1,'purpose':'FAILURE_DIAGNOSTIC_ONLY','outcome':'NOT_PASSED','commit':commit,'command':command,'profile':profile,
      'started_at':value['started_at'],'recorded_at':value['recorded_at'],'failed_phase':phase,'category':category,'elapsed_ms':failure['elapsedMs'],
      'exit_code':exit_code,'command_log_sha256':log_hash,'command_log_available':selected is not None,**projection,
      **({'repaired_scope':'SQL019_COMMAND_IDENTITY_ONLY','native_declared_effective_source_files':effective} if repaired else {}),
      'source_files':sources,'source_inventory_sha256':digest(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()),
      'cleanup':{name:flags.get(name) is True for name in ('ownedRemoved','resourceInventoryPreserved')},
      'limitations':['Failure diagnostics only; no successful qualification is inferred.','Only known phases, finite counters, exact static declaration coordinates and closed code classes are exported. Missing or unmapped output leaves the cause unknown.','Raw test titles, messages, SQL, values, stack traces, private paths and credentials remain private. Original assertions and deadlines are unchanged.',*(['Effective source hashes are admitted mount declarations; completed startup/exit readback and schema application are not inferred from this failure projection.'] if repaired else [])]}


def safe_report(root,value,commit):
    try:return _safe_report(root,value,commit)
    except (OSError,ValueError,TypeError,KeyError,IndexError,OverflowError,RuntimeError):return None


def load_report(root,commit):
    try:return safe_report(root,strict_json(read_file(root,REPORT,4*MIB)),commit)
    except (OSError,ValueError,TypeError,KeyError):return None


def safe_repaired_report(root,value,commit):
    try:return _safe_report(root,value,commit,repaired=True)
    except (OSError,ValueError,TypeError,KeyError,IndexError,OverflowError,RuntimeError):return None


def load_repaired_report(root,commit):
    try:return safe_repaired_report(root,strict_json(read_file(root,REPAIRED_REPORT,4*MIB)),commit)
    except (OSError,ValueError,TypeError,KeyError):return None
