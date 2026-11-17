#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify configurable PostgreSQL targets with real TLS on owned cached services.

Explicit launch only. No pull/build, published port, shared core mutation or
external database. Mounted source qualification is not baked-image attestation.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pg_target_base', ROOT/'scripts/runtime-test-authority-authn-foundation.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, sha, literal = base.require, base.sha, base.literal
LABEL = 'org.governance-commons.postgres-target-run'
LIVE = ROOT/'python/tests/postgres_targets_live.py'
CHECKS = ('mounted-source-and-runtime','verify-full-tls-and-pinned-address','metadata-only-scan',
          'wrong-hostname-refused','wrong-ca-refused','cidr-refused-before-connection',
          'tenant-scope-reference-refused','atomic-policy-rotation','atomic-credential-rotation',
          'privileged-role-refused','reduced-select-fails-completeness','stalled-ssl-negotiation-bounded')


def create_diagnostic(result):
    # A closed classification retains an actionable daemon refusal without
    # exporting mount paths, submitted arguments or arbitrary daemon output.
    message = result.stderr.lower()
    patterns = (
        ('DOCKER_STATIC_IP_REQUIRES_SUBNET', 'user specified ip address is supported only'),
        ('DOCKER_ADDRESS_UNAVAILABLE', 'address already in use'),
        ('DOCKER_INVALID_MOUNT', 'invalid mount config'),
        ('DOCKER_INVALID_VOLUME', 'invalid volume specification'),
        ('DOCKER_IMAGE_UNAVAILABLE', 'no such image'),
        ('DOCKER_NETWORK_UNAVAILABLE', 'network not found'),
        ('DOCKER_NAME_CONFLICT', 'is already in use by container'),
    )
    code = next((code for code, phrase in patterns if phrase in message), 'DOCKER_CREATE_FAILED_UNCLASSIFIED')
    return {'code':code,'exitCode':result.returncode,'stderrSha256':sha(result.stderr.encode())}


def sources():
    paths = [Path(__file__).resolve(), LIVE, ROOT/'scripts/runtime-test-authority-authn-foundation.py',
             ROOT/'python/Dockerfile', ROOT/'python/pyproject.toml', ROOT/'python/uv.lock', ROOT/'deploy/compose/compose.yaml']
    paths += sorted((ROOT/'python/governance_workers').glob('*.py'))
    require(all(p.is_file() and not p.is_symlink() for p in paths), 'Regular qualification source files required')
    return [{'path':str(p.relative_to(ROOT)), 'sha256':sha(p.read_bytes())} for p in sorted(paths)]


class Harness(base.Harness):
    def __init__(self):
        os.umask(0o077)
        self.id = 'gc-pg-target-' + uuid.uuid4().hex[:12]
        self.folder = ROOT/'.local/evidence'/('postgres-targets-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+self.id[-12:])
        self.folder.mkdir(parents=True, mode=0o700)
        self.phase, self.serial, self.output_bytes = 'admission', 0, 0
        self.deadline, self.cleanup_deadline = time.monotonic()+360, None
        self.private_values, self.containers = [], {}
        self.network, self.network_created, self.resources_before = self.id+'-network', False, None
        self.private = self.folder/'private'
        self.private.mkdir(mode=0o700)
        self.report = {'schema_version':1,'result':'RUNNING','started_at':datetime.now(timezone.utc).isoformat(),
                       'command':'python3 scripts/runtime-test-postgres-targets.py','profile':'isolated-postgres-targets-tls',
                       'evidenceMode':'mounted-source','checks':[]}

    def admission(self):
        super().admission()
        require(shutil.disk_usage(ROOT).free >= 2*base.GIB, 'Host free space below2GiB floor')

    def docker(self, *args, **kwargs):
        kwargs.setdefault('sensitive', True)
        return super().docker(*args, **kwargs)

    def inventory(self):
        result = super().inventory()
        result['networks'] = self.docker('network','ls','--no-trunc','--format','{{.ID}} {{.Name}}',sensitive=True).stdout.splitlines()
        return {key:sorted(values) for key, values in result.items()}

    def create(self, name, image, arguments, command=()):
        self.containers[name] = {'id':None,'image':image}
        result = self.docker('create','-i','--pull','never','--name',name,'--label',LABEL+'='+self.id,
                             '--log-driver','none','--read-only','--cap-drop','ALL',
                             '--security-opt','no-new-privileges:true',*arguments,image,*command,allow_failure=True)
        if result.returncode:
            self.report['containerCreateFailure'] = {'phase':self.phase,**create_diagnostic(result)}
            raise RuntimeError('Owned container create failed')
        ident = result.stdout.strip()
        require(re.fullmatch(r'[a-f0-9]{64}',ident), 'Owned container identity missing')
        self.containers[name]['id'] = ident
        return ident

    def cleanup(self):
        self.cleanup_deadline = time.monotonic()+60
        failures = []
        try:
            for name, expected in reversed(list(self.containers.items())):
                result = self.docker('inspect',name,allow_failure=True,cleanup=True)
                if result.returncode:
                    continue
                value = json.loads(result.stdout)[0]
                if (value['Config']['Labels'].get(LABEL) != self.id or value['Image'] != expected['image']
                        or expected['id'] is not None and value['Id'] != expected['id']):
                    failures.append('identity'); continue
                if self.docker('rm','-f',value['Id'],allow_failure=True,cleanup=True).returncode:
                    failures.append('container')
            result = self.docker('network','inspect',self.network,allow_failure=True,cleanup=True) if self.network_created else None
            if result is not None and result.returncode == 0:
                value = json.loads(result.stdout)[0]
                if value['Labels'].get(LABEL) != self.id or value.get('Containers'):
                    failures.append('network identity')
                elif self.docker('network','rm',value['Id'],allow_failure=True,cleanup=True).returncode:
                    failures.append('network')
        finally:
            # A Docker timeout must not retain generated private keys on host.
            if self.private.is_dir() and not self.private.is_symlink():
                shutil.rmtree(self.private)
        require(not self.private.exists(), 'Generated secret cleanup failed')
        if self.containers or self.network_created:
            require(not self.docker('ps','-aq','--filter','label='+LABEL+'='+self.id,cleanup=True).stdout.strip(), 'Owned containers remain')
            require(not self.docker('network','ls','-q','--filter','label='+LABEL+'='+self.id,cleanup=True).stdout.strip(), 'Owned networks remain')
        require(not failures, 'Owned resource cleanup failed')
        self.report['cleanup'] = {'ownedRemoved':True,'generatedSecretsRemoved':True}


def certificates(h):
    openssl = shutil.which('openssl')
    require(openssl is not None, 'Local OpenSSL is required')
    h.report['openssl'] = h.command([openssl,'version'],sensitive=True).stdout.strip()
    for prefix in ('ca','wrong-ca'):
        h.command([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256',
                   '-subj','/CN=Synthetic PostgreSQL qualification '+prefix,
                   '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
                   '-keyout',str(h.private/(prefix+'.key')),'-out',str(h.private/(prefix+'.crt'))],sensitive=True,timeout=30)
    h.command([openssl,'req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=pg-target.test',
               '-keyout',str(h.private/'server.key'),'-out',str(h.private/'server.csr')],sensitive=True,timeout=30)
    (h.private/'server.ext').write_text('subjectAltName=DNS:pg-target.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    h.command([openssl,'x509','-req','-days','1','-sha256','-in',str(h.private/'server.csr'),
               '-CA',str(h.private/'ca.crt'),'-CAkey',str(h.private/'ca.key'),'-CAcreateserial',
               '-extfile',str(h.private/'server.ext'),'-out',str(h.private/'server.crt')],sensitive=True,timeout=30)
    require(all(p.stat().st_mode & 0o077 == 0 for p in h.private.iterdir()), 'Generated credential file modes unsafe')


def execute(h):
    require(os.name == 'posix', 'POSIX qualification required')
    frozen = sources()
    h.report['sources'] = frozen
    h.report['commit'] = h.command(['git','rev-parse','HEAD'],sensitive=True).stdout.strip()
    context = json.loads(h.docker('context','inspect').stdout)[0]['Endpoints']['docker']['Host']
    require(context.startswith('unix://') and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://')), 'Local Docker only')
    h.resources_before = h.inventory()
    h.report['memoryAdmission'] = h.memory_admission()
    pg_ref = re.search(r'^\s+image: (postgres:17-[^\s]+@sha256:[a-f0-9]{64})$',(ROOT/'deploy/compose/compose.yaml').read_text(),re.M)
    require(pg_ref is not None, 'Pinned PostgreSQL17 image missing')
    pg_image = h.docker('image','inspect','--format','{{.Id}}',pg_ref[1]).stdout.strip()
    worker_image = h.docker('image','inspect','--format','{{.Id}}','governance-commons-python:dev').stdout.strip()
    require(all(re.fullmatch(r'sha256:[a-f0-9]{64}',v) for v in (pg_image,worker_image)), 'Cached immutable image IDs required')
    h.report['images'] = {'postgres':pg_image,'python':worker_image}
    h.phase = 'certificates'
    certificates(h)
    h.phase = 'network'
    h.network_created = True
    h.docker('network','create','--driver','bridge','--internal','--label',LABEL+'='+h.id,h.network)
    network = json.loads(h.docker('network','inspect',h.network).stdout)[0]
    require(network['Internal'] is True and network['Driver'] == 'bridge' and not network['EnableIPv6'], 'Isolated IPv4 bridge required')
    cidrs = [ipaddress.ip_network(row['Subnet']) for row in network['IPAM']['Config']]
    require(len(cidrs)==1 and cidrs[0].version==4, 'Exact Docker subnet required')
    h.report['network'] = {'id':network['Id'],'subnet':str(cidrs[0]),'internal':True,'publishedPorts':False}
    h.phase = 'database'
    # Start waits for private stdin transfer before opening its listener. A fixed
    # timeout prevents an interrupted provisioner leaving an indefinite wait.
    startup = """initdb --auth-local=trust --auth-host=scram-sha-256 -D /var/lib/postgresql/data/pgdata >/tmp/init.log 2>&1
mkdir -m700 /tmp/tls
i=0; while [ ! -f /tmp/tls/ready ]; do i=$((i+1)); [ "$i" -lt 60 ] || exit 1; sleep 1; done
printf 'local all all trust\nhostnossl all all 0.0.0.0/0 reject\nhostssl all all 0.0.0.0/0 scram-sha-256\n' > /var/lib/postgresql/data/pgdata/pg_hba.conf
exec postgres -D /var/lib/postgresql/data/pgdata -c listen_addresses='*' -c ssl=on -c ssl_cert_file=/tmp/tls/server.crt -c ssl_key_file=/tmp/tls/server.key -c ssl_min_protocol_version=TLSv1.2 -c shared_buffers=32MB -c work_mem=2MB -c max_connections=16 -c min_wal_size=32MB -c max_wal_size=64MB -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse -c log_parameter_max_length=0 -c log_parameter_max_length_on_error=0
"""
    h.create(h.id,pg_image,['--network',h.network,'--network-alias','pg-target.test','--network-alias','wrong-target.test',
             '--user','postgres','--memory','384m','--memory-swap','384m','--cpus','1','--pids-limit','64',
             '--tmpfs','/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,mode=1777',
             '--tmpfs','/tmp:rw,nosuid,nodev,size=16m,mode=1777','--tmpfs','/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777',
             '--entrypoint','sh'], ['-ec',startup])
    h.docker('start',h.id)
    until = time.monotonic()+30
    while h.docker('exec',h.id,'test','-d','/tmp/tls',allow_failure=True).returncode:
        require(time.monotonic()<until, 'Private TLS directory readiness timed out')
        time.sleep(.1)
    for name in ('server.key','server.crt'):
        h.docker('exec','-i',h.id,'sh','-ec','umask 077; cat > /tmp/tls/'+name,
                 input=(h.private/name).read_bytes())
    h.docker('exec',h.id,'touch','/tmp/tls/ready')
    while h.docker('exec',h.id,'pg_isready','-U','postgres',allow_failure=True).returncode:
        require(time.monotonic()<until, 'TLS PostgreSQL readiness timed out')
        time.sleep(.1)
    observed = json.loads(h.docker('inspect',h.id).stdout)[0]
    require(observed['Image']==pg_image and observed['State']['Running'] is True and not observed['HostConfig']['PortBindings'], 'Owned PostgreSQL identity differs')
    require(set(observed['NetworkSettings']['Networks'])=={h.network}, 'Unexpected database network')
    address = observed['NetworkSettings']['Networks'][h.network]['IPAddress']
    require(ipaddress.ip_address(address) in cidrs[0], 'Database address is outside observed subnet')
    h.report['network']['databaseAddress'] = address
    admin_password, reader_password, wrong_password, marker = [secrets.token_hex(24) for _ in range(4)]
    h.private_values = [admin_password,reader_password,wrong_password,marker]
    def sql(body, database='qualification'):
        return h.docker('exec','-i',h.id,'psql','-X','-qAt','--set','ON_ERROR_STOP=1','-U','postgres','-d',database,input=body)
    require(json.loads(sql("SELECT json_agg(json_build_array(type,auth_method,error) ORDER BY rule_number) FROM pg_hba_file_rules;",'postgres').stdout)==[
                ['local','trust',None],['hostnossl','reject',None],['hostssl','scram-sha-256',None]], 'Closed TLS/SCRAM HBA differs')
    sql(f"ALTER ROLE postgres PASSWORD {literal(admin_password)};CREATE ROLE metadata_reader LOGIN PASSWORD {literal(reader_password)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;CREATE DATABASE qualification;",'postgres')
    sql("REVOKE ALL ON DATABASE qualification FROM PUBLIC;GRANT CONNECT ON DATABASE qualification TO metadata_reader;"
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;CREATE SCHEMA inventory;GRANT USAGE ON SCHEMA inventory TO metadata_reader;"
        "CREATE TABLE inventory.orders(id integer PRIMARY KEY,payload text NOT NULL);"
        f"INSERT INTO inventory.orders VALUES(1,{literal(marker)});"
        "CREATE FUNCTION inventory.never_read_rows() RETURNS text LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_BUSINESS_ROW_READ';END$$;"
        "CREATE VIEW inventory.never_read AS SELECT inventory.never_read_rows() AS value;"
        "GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO metadata_reader;")
    mounted = [{'path':row['path'].removeprefix('python/'),'sha256':row['sha256']} for row in frozen
               if row['path'].startswith('python/governance_workers/') or row['path']=='python/tests/postgres_targets_live.py']
    config = {'tenant':'synthetic-postgres-qualification','address':address,'readerPassword':reader_password,
              'adminPassword':admin_password,'wrongPassword':wrong_password,'rowMarker':marker,
              'caPem':(h.private/'ca.crt').read_text(),'wrongCaPem':(h.private/'wrong-ca.crt').read_text(),
              'sources':mounted,'lockSha256':sha((ROOT/'python/uv.lock').read_bytes()),
              'projectSha256':sha((ROOT/'python/pyproject.toml').read_bytes())}
    h.phase = 'live-tests'
    worker = h.id+'-worker'
    h.create(worker,worker_image,['--network',h.network,'--network-alias','stalled-target.test','--user',f'{os.getuid()}:{os.getgid()}',
             '--memory','384m','--memory-swap','384m','--cpus','1','--pids-limit','64',
             '--tmpfs','/tmp:rw,nosuid,nodev,size=32m,mode=1777','--workdir','/worker',
             '--env','HOME=/tmp','--env','PYTHONPATH=/worker','--env','PYTHONDONTWRITEBYTECODE=1',
             '--volume',f'{ROOT / "python/governance_workers"}:/worker/governance_workers:ro',
             '--volume',f'{LIVE}:/worker/tests/postgres_targets_live.py:ro',
             '--entrypoint','/worker/.venv/bin/python'],['/worker/tests/postgres_targets_live.py'])
    worker_config = json.loads(h.docker('inspect',worker).stdout)[0]
    require(worker_config['Image']==worker_image and not worker_config['HostConfig']['PortBindings'], 'Worker image differs')
    expected_mounts = {('/worker/governance_workers',str(ROOT/'python/governance_workers')),
                       ('/worker/tests/postgres_targets_live.py',str(LIVE))}
    require({(m['Destination'],m['Source']) for m in worker_config['Mounts'] if m['Type']=='bind'}==expected_mounts
            and all(m['RW'] is False for m in worker_config['Mounts'] if m['Type']=='bind'), 'Mounted source attestation differs')
    h.report['sourceMounts'] = [{'destination':destination,'mode':'read-only'} for destination,_ in sorted(expected_mounts)]
    # The stdin-open process waits for one bounded JSON line. Start first so
    # Docker assigns an address, then bind policy to that observed address.
    h.docker('start',worker)
    started = json.loads(h.docker('inspect',worker).stdout)[0]
    require(started['Id']==h.containers[worker]['id'] and started['Image']==worker_image
            and started['State']['Running'] is True and started['State']['OOMKilled'] is False
            and set(started['NetworkSettings']['Networks'])=={h.network}, 'Running worker identity unavailable')
    worker_address = started['NetworkSettings']['Networks'][h.network]['IPAddress']
    require(ipaddress.ip_address(worker_address) in cidrs[0] and worker_address!=address
            and worker_address not in [row.get('Gateway') for row in network['IPAM']['Config']], 'Observed worker address unavailable')
    h.report['network']['workerAddress'] = worker_address
    config['workerAddress'] = worker_address
    payload = json.dumps(config)+'\n'
    require(len(payload.encode())<=1024*1024, 'Private configuration exceeds frame bound')
    result = h.docker('attach','--sig-proxy=false',worker,input=payload,timeout=180,allow_failure=True)
    observed = json.loads(h.docker('inspect',worker).stdout)[0]
    require(observed['Id']==h.containers[worker]['id'] and observed['Image']==worker_image
            and observed['State']['Running'] is False and observed['State']['OOMKilled'] is False, 'Worker terminal state unavailable')
    h.report['workerExit'] = {'exitCode':observed['State']['ExitCode'],'oomKilled':False}
    try:
        outcome = json.loads(result.stdout)
    except (ValueError,TypeError):
        raise RuntimeError('Closed live qualification result unavailable') from None
    require(type(outcome) is dict and outcome.get('result') in ('PASS','FAIL'), 'Invalid live qualification result')
    if outcome['result']=='FAIL':
        require(set(outcome)=={'result','checks','failedCase','code'} and type(outcome['checks']) is list
                and outcome['checks']==list(CHECKS[:len(outcome['checks'])])
                and outcome['failedCase']==(CHECKS[len(outcome['checks'])] if len(outcome['checks'])<len(CHECKS) else 'final-source-check')
                and re.fullmatch(r'[A-Z_]{1,64}',outcome['code']), 'Unsafe live failure result')
        h.report['liveFailure'] = {'case':outcome['failedCase'],'code':outcome['code']}
        h.report['checks'] = outcome['checks']
    require(result.returncode==0 and observed['State']['ExitCode']==0 and outcome['result']=='PASS', 'Live TLS qualification failed')
    require(set(outcome)=={'result','checks','runtime'} and outcome['checks']==list(CHECKS)
            and set(outcome['runtime'])=={'python','psycopg','libpq','sourceHashes'}
            and outcome['runtime']['sourceHashes']==mounted
            and all(re.fullmatch(r'\d+\.\d+\.\d+',outcome['runtime'][key]) for key in ('python','psycopg'))
            and type(outcome['runtime']['libpq']) is int and outcome['runtime']['libpq']>=170000, 'Incomplete live qualification')
    h.report['checks'] = outcome['checks']
    h.report['runtime'] = outcome['runtime']
    h.report['workerExit'] = {'exitCode':observed['State']['ExitCode'],'oomKilled':False}
    require(sources()==frozen, 'Source changed during isolated qualification')
    h.report['limitations'] = ['Current adapter/helper source mounted read-only into cached Python dependencies; not immutable application-image qualification.',
        'Synthetic isolated PostgreSQL17 TLS/SCRAM metadata scan only; no external database or Temporal/API/UI execution.',
        'CIDR rejection proves the real parameter builder refuses before yielding connection parameters; no packet-capture claim.',
        'Generated policy/provider rotation is exercised in the worker process; no operating-system or vendor production qualification.']


def main():
    h = Harness()
    failed = False
    try:
        execute(h)
    except BaseException:
        failed = True
        h.report.update(result='FAIL',failedPhase=h.phase,error='QUALIFICATION_FAILED')
    finally:
        try:
            h.phase = 'cleanup'
            h.cleanup()
            if h.resources_before is not None:
                h.deadline = h.cleanup_deadline
                require(h.inventory() == h.resources_before, 'Preexisting Docker inventory changed')
                h.report['cleanup']['preexistingInventoryPreserved'] = True
        except BaseException:
            failed = True
            h.report['cleanupError'] = 'CLEANUP_NOT_CONFIRMED'
        h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat())
        (h.folder/'report.json').write_text(json.dumps(h.report,indent=2)+'\n')
    print(json.dumps({'result':h.report['result'],'report':str((h.folder/'report.json').relative_to(ROOT))}))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
