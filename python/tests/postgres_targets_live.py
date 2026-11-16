# SPDX-License-Identifier: Apache-2.0
"""Explicit isolated native qualification; never discovered by unittest.

The owner harness supplies one bounded private JSON document on stdin. No
credential, exception text, source records or connection string is printed.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import sys
import tempfile
import threading
import time

import psycopg
from governance_workers import postgresql, postgres_targets, secrets
from governance_workers.deadline import deadline

CHECKS = (
    'mounted-source-and-runtime', 'verify-full-tls-and-pinned-address',
    'metadata-only-scan', 'wrong-hostname-refused', 'wrong-ca-refused',
    'cidr-refused-before-connection', 'tenant-scope-reference-refused',
    'atomic-policy-rotation', 'atomic-credential-rotation',
    'privileged-role-refused', 'reduced-select-fails-completeness', 'stalled-ssl-negotiation-bounded',
)


def require(condition):
    if not condition:
        raise AssertionError('QUALIFICATION_ASSERTION_FAILED')


def atomic(path, value):
    temporary = path.with_suffix('.next')
    with temporary.open('x', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        stream.write(json.dumps(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    require(path.stat().st_mode & 0o777 == 0o600)


def failure(code, call):
    try:
        call()
    except (postgresql.ScanFailure, postgres_targets.TargetPolicyError) as error:
        require(error.code == code and str(error) == code)
        return
    raise AssertionError('QUALIFICATION_EXPECTED_REFUSAL')


def execute(config, passed):
    def source_hashes():
        return [{'path': row['path'], 'sha256': hashlib.sha256(Path('/worker', row['path']).read_bytes()).hexdigest()}
                for row in config['sources']]
    require(source_hashes() == config['sources'])
    require(hashlib.sha256(Path('/worker/uv.lock').read_bytes()).hexdigest() == config['lockSha256'])
    require(hashlib.sha256(Path('/worker/pyproject.toml').read_bytes()).hexdigest() == config['projectSha256'])
    require(psycopg.pq.version() >= 170000)
    passed.append(CHECKS[0])
    tenant, ref = config['tenant'], 'tls-reader'
    source = {'connectorId': 'postgresql', 'secretRef': ref, 'host': 'pg-target.test',
              'port': 5432, 'database': 'qualification', 'schema': 'inventory'}
    credential = dict(source, tenantIds=[tenant], username='metadata_reader', password=config['readerPassword'])
    target = {key: source[key] for key in ('host', 'port', 'database', 'schema')}
    target.update(tenantIds=[tenant], allowedCidrs=[config['address']+'/32'],
                  tls={'mode': 'verify-full', 'caPem': config['caPem']})
    policy = {'formatVersion': 1, 'targets': {ref: target}}
    with tempfile.TemporaryDirectory(prefix='gc-live-pg-') as directory:
        os.chmod(directory, 0o700)
        policy_path, provider_path = Path(directory, 'targets.json'), Path(directory, 'secrets.json')
        atomic(policy_path, policy)
        atomic(provider_path, {ref: credential})
        os.environ['POSTGRES_TARGETS_FILE'] = str(policy_path)

        def scan(current_source=source):
            current_secret = secrets.resolve(provider_path, current_source['secretRef'], tenant, 'postgresql')
            return postgresql.scan(current_source, current_secret, tenant)

        @contextmanager
        def connection(secret=credential, *, admin=False):
            end = time.monotonic()+20
            with deadline(20), postgres_targets.prepare_connection(postgres_targets.load_policy(policy_path), source, secret,
                    tenant, deadline_at=end) as params:
                require(params['hostaddr'] == config['address'] and params['sslmode'] == 'verify-full'
                        and params['ssl_min_protocol_version'] == 'TLSv1.2' and params['sslcertmode'] == 'disable')
                values = dict(params)
                if admin:
                    # Only this fixture-control connection writes; the adapter
                    # always receives its own fixed read-only options unchanged.
                    values['options'] = '-c search_path=pg_catalog -c statement_timeout=15000 -c lock_timeout=2000'
                conn = psycopg.connect(**values, autocommit=True)
                try:
                    yield conn
                finally:
                    conn.close()

        with connection() as conn:
            row = conn.execute('SELECT ssl,version,bits FROM pg_stat_ssl WHERE pid=pg_backend_pid()').fetchone()
            require(row and row[0] is True and row[1] in ('TLSv1.2', 'TLSv1.3') and row[2] >= 128)
            require(conn.execute("SELECT current_setting('transaction_read_only')").fetchone()[0] == 'on')
        passed.append(CHECKS[1])
        result = scan()
        require(result['complete'] is True)
        records = result['records']
        require(sorted((r['type'], r['qualifiedName']) for r in records) == sorted([
            ('schema','qualification.inventory'), ('table','qualification.inventory.orders'),
            ('column','qualification.inventory.orders.id'), ('column','qualification.inventory.orders.payload'),
            ('view','qualification.inventory.never_read'), ('column','qualification.inventory.never_read.value')]))
        require(config['rowMarker'] not in json.dumps(result))
        # The view calls a raising function if evaluated; metadata enumeration
        # succeeds without reading that view or returning synthetic business rows.
        passed.append(CHECKS[2])
        wrong_source = dict(source, host='wrong-target.test')
        wrong_secret = dict(credential, host='wrong-target.test')
        wrong_policy = {'formatVersion': 1, 'targets': {ref: dict(target, host='wrong-target.test')}}
        atomic(policy_path, wrong_policy)
        failure('SOURCE_DATABASE_ERROR', lambda: postgresql.scan(wrong_source, wrong_secret, tenant))
        atomic(policy_path, policy)
        passed.append(CHECKS[3])
        wrong_ca = {'formatVersion': 1, 'targets': {ref: dict(target, tls={'mode':'verify-full','caPem':config['wrongCaPem']})}}
        atomic(policy_path, wrong_ca)
        failure('SOURCE_DATABASE_ERROR', scan)
        atomic(policy_path, policy)
        passed.append(CHECKS[4])
        denied = {'formatVersion': 1, 'targets': {ref: dict(target, allowedCidrs=['192.0.2.0/24'])}}
        atomic(policy_path, denied)
        def cannot_prepare():
            with postgres_targets.prepare_connection(postgres_targets.load_policy(policy_path), source, credential,
                    tenant, deadline_at=time.monotonic()+20):
                raise AssertionError('DENIED_TARGET_REACHED_CONNECT_BOUNDARY')
        failure('SOURCE_DESTINATION_DENIED', cannot_prepare)
        failure('SOURCE_DESTINATION_DENIED', scan)
        atomic(policy_path, policy)
        passed.append(CHECKS[5])
        failure('SOURCE_SCOPE_DENIED', lambda: postgresql.scan(source, credential, 'foreign-tenant'))
        failure('SOURCE_TARGET_DENIED', lambda: postgresql.scan(dict(source, schema='other'), credential, tenant))
        failure('SOURCE_TARGET_DENIED', lambda: postgresql.scan(dict(source, secretRef='unregistered'), credential, tenant))
        failure('SOURCE_TARGET_DENIED', lambda: postgresql.scan(source, dict(credential, secretRef='different'), tenant))
        passed.append(CHECKS[6])
        original_inode = policy_path.stat().st_ino
        atomic(policy_path, denied)
        require(policy_path.stat().st_ino != original_inode)
        failure('SOURCE_DESTINATION_DENIED', scan)
        atomic(policy_path, policy)
        require(scan()['complete'] is True)
        passed.append(CHECKS[7])
        original_inode = provider_path.stat().st_ino
        atomic(provider_path, {ref:dict(credential, password=config['wrongPassword'])})
        require(provider_path.stat().st_ino != original_inode)
        failure('SOURCE_DATABASE_ERROR', scan)
        atomic(provider_path, {ref:credential})
        require(scan()['complete'] is True)
        passed.append(CHECKS[8])
        admin_secret = dict(credential, username='postgres', password=config['adminPassword'])
        failure('SOURCE_PRIVILEGE_TOO_BROAD', lambda: postgresql.scan(source, admin_secret, tenant))
        passed.append(CHECKS[9])
        with connection(admin_secret, admin=True) as conn:
            conn.execute('REVOKE SELECT ON inventory.orders FROM metadata_reader')
        try:
            failure('SOURCE_SCOPE_INCOMPLETE', scan)
        finally:
            with connection(admin_secret, admin=True) as conn:
                conn.execute('GRANT SELECT ON inventory.orders TO metadata_reader')
        require(scan()['complete'] is True)
        passed.append(CHECKS[10])
        # Real libpq client, real Docker DNS and a real peer that receives an
        # SSLRequest but never acknowledges it. No resolver/driver replacement.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stop = threading.Event()
        ssl_request = []
        worker_errors = []
        listener.bind(('0.0.0.0',0))
        listener.listen(1)
        listener.settimeout(.2)
        port = listener.getsockname()[1]
        def stall():
            try:
                end = time.monotonic()+10
                while not stop.is_set():
                    try:
                        peer, _ = listener.accept()
                        break
                    except socket.timeout:
                        if time.monotonic()>=end:
                            worker_errors.append('ACCEPT_TIMEOUT')
                            return
                else:
                    return
                with peer:
                    peer.settimeout(2)
                    request = b''
                    while len(request)<8:
                        block = peer.recv(8-len(request))
                        if not block:
                            break
                        request += block
                    ssl_request.append(request)
                    stop.wait(10)
            except OSError:
                if not stop.is_set():
                    worker_errors.append('SOCKET_ERROR')
        thread = threading.Thread(target=stall,daemon=False)
        started = False
        try:
            thread.start()
            started = True
            stalled_source = dict(source, host='stalled-target.test', port=port)
            stalled_secret = dict(credential, host='stalled-target.test', port=port)
            stalled_target = dict(target, host='stalled-target.test', port=port, allowedCidrs=[config['workerAddress']+'/32'])
            atomic(policy_path, {'formatVersion':1,'targets':{ref:stalled_target}})
            start = time.monotonic()
            failure('SOURCE_DATABASE_ERROR', lambda: postgresql.scan(stalled_source,stalled_secret,tenant))
            elapsed = time.monotonic()-start
            require(4 <= elapsed <= 8 and ssl_request == [b'\x00\x00\x00\x08\x04\xd2\x16\x2f'] and not worker_errors)
        finally:
            stop.set()
            listener.close()
            if started:
                thread.join(timeout=2)
                require(not thread.is_alive())
            require(listener.fileno()==-1)
            atomic(policy_path, policy)
        passed.append(CHECKS[11])
    require(source_hashes() == config['sources'])
    return {'python':platform.python_version(), 'psycopg':psycopg.__version__, 'libpq':psycopg.pq.version(),
            'sourceHashes':source_hashes()}


def main():
    os.umask(0o077)
    passed = []
    try:
        # Docker starts this stdin-open worker before its exact IP is known.
        # A bounded newline frame releases it without waiting for attach EOF.
        raw = sys.stdin.buffer.readline(1024*1024+1)
        require(0 < len(raw) <= 1024*1024 and raw.endswith(b'\n'))
        config = json.loads(raw)
        runtime = execute(config, passed)
        require(tuple(passed) == CHECKS)
        print(json.dumps({'result':'PASS','checks':passed,'runtime':runtime}))
        return 0
    except BaseException as error:
        code = error.code if isinstance(error, (postgresql.ScanFailure, postgres_targets.TargetPolicyError)) else 'QUALIFICATION_ASSERTION_FAILED'
        print(json.dumps({'result':'FAIL','checks':passed,'failedCase':CHECKS[len(passed)] if len(passed)<len(CHECKS) else 'final-source-check','code':code}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
