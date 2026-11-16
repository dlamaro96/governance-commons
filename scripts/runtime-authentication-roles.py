#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision local SQL012 role prerequisites through private Compose stdin."""
import argparse
import subprocess

from authentication_roles import prepare_sql, finish_sql, executor_sql
from runtime import COMPOSE, ROOT, authentication_bootstrap, require_bootstrap, require_local


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'finish', 'executors'])
    phase = parser.parse_args().phase
    require_bootstrap()
    require_local()
    if phase == 'prepare':
        body = prepare_sql('gc_owner', 'governance')
    elif phase == 'finish':
        body = finish_sql('gc_owner')
    else:
        values = authentication_bootstrap()
        body = executor_sql('governance', [
            {'name': 'gc_authn_login', 'kind': 'login', 'password': values['GC_AUTHN_LOGIN_PASSWORD']},
            {'name': 'gc_authn_api', 'kind': 'api', 'password': values['GC_AUTHN_API_PASSWORD']},
        ])
    # The local postgres container authenticates its administrator through its
    # own Unix socket. No administrator URL or password is passed to the app.
    # SQL/passwords and database errors are deliberately absent from public logs.
    result = subprocess.run([*COMPOSE, 'exec', '-T', 'postgres', 'psql', '-X', '-q',
        '--set', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'governance'],
        cwd=ROOT, input=body, text=True, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode:
        raise SystemExit(f'Authentication deployment {phase} failed; no successful installation is claimed.')
    print(f'Authentication deployment {phase}: PASS (inactive foundation only).')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        raise SystemExit('Authentication deployment failed; private inputs were not logged.')
