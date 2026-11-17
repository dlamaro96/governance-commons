#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fixed SQL029 module bindings for the five affected historical quality gates.

SQL026 repository bindings remain authoritative where required. No current or
post030 gate imports this selector; unknown native phases fail closed.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('quality_pre030_repository',ROOT/'scripts/qualification_quality_repository.py')
repository=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(repository)
require=repository.require
SERVICE='packages/domain/src/quality-service.ts'
REPOSITORY=repository.REPOSITORY
COMMIT='fca6bb94a8bd87965c4bf614ae492b85235f4ea9'
BINDINGS={
 SERVICE:('tests/qualification/predecessors/quality-service-sql029.ts.txt','6a7691da7bf328341277ad0cf6737f44b5fd25cc61dbb97b2b345ecec14e1a73','289dfdd222f7949d1aaabdb35c46cc48b7a5e975'),
 REPOSITORY:('tests/qualification/predecessors/repository-sql029.ts.txt','0b3305e0318db339031dee812b6c06d742f32c8af8b5a44b601b4d50569d9eed','c29e13fa15bbbfb4c4a7c0182f853e89f9ee1f60'),
}
COMMON=('completeness','reference','uniqueness','range')
MONITORING=(*COMMON,'monitoring','monitoring-invariants')
FRESHNESS=(*MONITORING,'freshness','freshness-invariants')
PHASES={
 'uniqueness':repository.PHASES['uniqueness'],
 'range':repository.PHASES['range'],
 'monitoring':frozenset(f'{stage}-{family}-tests' for stage in ('pre026','post027') for family in COMMON)|frozenset(('post027-monitoring-tests','post027-monitoring-invariants-tests')),
 'freshness':frozenset(f'{stage}-{family}-tests' for stage in ('pre027','post028') for family in MONITORING)|frozenset(('post028-freshness-tests','post028-freshness-invariants-tests')),
 'freshness-scheduling':frozenset(f'{stage}-{family}-tests' for stage in ('pre028','post029') for family in FRESHNESS)|frozenset(('post029-freshness-monitoring-tests','post029-freshness-monitoring-invariants-tests')),
}
INPUTS=frozenset(('scripts/qualification_quality_pre030.py','scripts/qualification_quality_repository.py',repository.FIXTURE,*(x[0] for x in BINDINGS.values())))


def historical_imports(root, relative):
    """Resolve retained imports at their actual mounted module path."""
    selected=[]
    if relative in BINDINGS:selected.append(BINDINGS[relative][:2])
    if relative==REPOSITORY:selected.append((repository.FIXTURE,repository.DIGEST))
    return '\n'.join(repository.checked(root,path,digest).read_text() for path,digest in selected)


def select(root,frozen,gate,phase):
    require(gate in PHASES,'Unknown historical quality gate')
    require(isinstance(phase,str),'Unknown historical quality phase')
    require(not phase.endswith('-tests') or phase in PHASES[gate],'Unknown historical quality native phase')
    sources=[dict(row) for row in frozen]
    require(all(set(row)=={'path','sha256'} and isinstance(row['path'],str) and re.fullmatch(r'[a-f0-9]{64}',row['sha256']) for row in sources)
            and len({row['path'] for row in sources})==len(sources),'Historical quality source inventory malformed')
    if phase not in PHASES[gate]:return {'sources':sources,'override':None,'overrides':[]}
    prior=repository.select(root,frozen,gate,phase) if gate in repository.PHASES else {'sources':sources,'override':None}
    effective=prior['sources'];overrides=[] if prior['override'] is None else [prior['override']]
    for target,(fixture,digest,blob) in BINDINGS.items():
        if any(item['path']==target for item in overrides):continue
        matches=[row for row in sources if row['path']==target]
        require(len(matches)==1 and {'path':fixture,'sha256':digest} in sources,'Historical quality source inventory omits immutable binding')
        repository.checked(root,target,matches[0]['sha256'])
        path=repository.checked(root,fixture,digest);data=path.read_bytes()
        require(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'Historical quality Git blob differs')
        effective=[{**row,'sha256':digest} if row['path']==target else row for row in effective]
        overrides.append({'path':target,'fixture':fixture,'commit':COMMIT,'gitBlob':blob,'sha256':digest,'checkoutSha256':matches[0]['sha256'],'readOnly':True,'mountTarget':'/app/'+target})
    require(len({item['path'] for item in overrides})==len(overrides),'Duplicate historical quality target')
    return {'sources':effective,'override':next(item for item in overrides if item['path']==REPOSITORY),'overrides':overrides}


def mounted_path(root,row,selected):
    matches=[item for item in selected['overrides'] if item['path']==row['path']]
    require(len(matches)<=1,'Duplicate historical quality mount')
    return root/(matches[0]['fixture'] if matches else row['path'])
