#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned POSIX browser groups; never signal by executable/name or global matching.

Playwright1.65.1 launches Chromium in a separate POSIX group. A private launcher
handshake records that group before exec. This bounds registered groups and
observed descendants, not arbitrary unobserved adversarial double-fork escape.
"""
from __future__ import annotations
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

CAP = 4*1024*1024
MAX_PROCESSES = 4096


def require(ok):
    if not ok:
        raise RuntimeError('Owned browser process boundary rejected')


def digest(path):
    require(path.is_file() and path.stat().st_size <= 256*1024*1024)
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def identity(pid):
    """Kernel start identity, not the one-second precision ps lstart string."""
    require(type(pid) is int and pid > 1)
    if sys.platform == 'darwin':
        # Public Darwin PROC_PIDTBSDINFO ABI, including microsecond birth time:
        # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
        library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        library.proc_pidinfo.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(136)
        ctypes.set_errno(0)
        length = library.proc_pidinfo(pid, 3, 0, buffer, 136)
        if length == 0 and ctypes.get_errno() in (0, errno.ESRCH):
            return None
        require(length == 136)
        values = struct.unpack('=12I16s32s6I2Q', buffer.raw)
        require(values[3] == pid)
        return {'pid': pid, 'ppid': values[4], 'pgid': values[15], 'uid': values[5],
                'start': f'darwin:{values[20]}:{values[21]}', 'live': values[1] != 5}
    require(sys.platform.startswith('linux'))
    try:
        path = Path('/proc')/str(pid)
        data = (path/'stat').read_text()
        tail = data.rsplit(')', 1)[1].split()
        return {'pid': pid, 'ppid': int(tail[1]), 'pgid': int(tail[2]), 'uid': path.stat().st_uid,
                'start': 'linux:'+tail[19], 'live': tail[0] != 'Z'}
    except FileNotFoundError:
        return None


def same(left, right):
    return right is not None and all(left[k] == right[k] for k in ('pid', 'pgid', 'uid', 'start'))


def table():
    result = subprocess.run(['ps', '-axo', 'pid=,ppid=,pgid='], capture_output=True, timeout=2)
    require(result.returncode == 0 and len(result.stdout) <= 1024*1024 and not result.stderr)
    rows = {}
    for line in result.stdout.decode('ascii').splitlines():
        parts = line.split()
        require(len(parts) == 3 and all(re.fullmatch(r'[0-9]+', x) for x in parts))
        pid, parent, group = map(int, parts)
        rows[pid] = (parent, group)
    require(len(rows) <= 16384)
    return rows


def read_private(path, maximum=4096):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= maximum)
        data = os.read(fd, maximum+1)
        require(len(data) <= maximum)
        return json.loads(data)
    finally:
        os.close(fd)


def write_private(path, value):
    data = (json.dumps(value, separators=(',', ':'))+'\n').encode()
    require(len(data) <= 4096)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        require(os.write(fd, data) == len(data))
        os.fsync(fd)
    finally:
        os.close(fd)


def launcher():
    control_path = Path(os.environ['GC_PROTECTED_BROWSER_CONTROL'])
    control = read_private(control_path)
    require(set(control) == {'version', 'token', 'executable', 'sha256'})
    require(control['version'] == 1 and re.fullmatch('[a-f0-9]{64}', control['token']))
    directory = control_path.parent/'registry'
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    binary = Path(control['executable'])
    require(binary.is_absolute() and digest(binary) == control['sha256'])
    current = identity(os.getpid())
    require(current is not None and current['pid'] == current['pgid'] and current['uid'] == os.getuid() and not (directory/'closed').exists())
    record = {k: current[k] for k in ('pid', 'ppid', 'pgid', 'uid', 'start')}
    record['token'] = control['token']
    pending = directory/('pending-'+secrets.token_hex(8))
    write_private(pending, record)
    try:
        os.link(pending, directory/(str(current['pid'])+'.json'))
    finally:
        pending.unlink()
    end = time.monotonic()+10
    ack = directory/(str(current['pid'])+'.ack')
    while not ack.exists():
        require(time.monotonic() < end and not (directory/'closed').exists())
        time.sleep(.025)
    require(read_private(ack) == {'token': control['token']} and not (directory/'closed').exists())
    # Exec preserves PID/start/group, every supplied Chrome argument and trusted env.
    os.execv(str(binary), [str(binary), *sys.argv[1:]])


def command_gate():
    # Do not exec the CLI (which could create descendants) until its parent has
    # installed identity tracking and pipe selectors. No child is spawned here.
    control_path = Path(os.environ['GC_PROTECTED_BROWSER_CONTROL'])
    control = read_private(control_path)
    require(control['version'] == 1 and re.fullmatch('[a-f0-9]{64}',control['token']))
    ack = control_path.parent/'command.ack'
    end = time.monotonic()+10
    while not ack.exists():
        require(time.monotonic() < end and not (control_path.parent/'registry/closed').exists())
        time.sleep(.025)
    require(read_private(ack) == {'token':control['token']})
    require(len(sys.argv) >= 3)
    os.execvpe(sys.argv[2],sys.argv[2:],os.environ)


class Tracker:
    def __init__(self, root, directory, token):
        require(root is not None and root['pid'] == root['pgid'] and root['pgid'] != os.getpgrp() and root['uid'] == os.getuid())
        self.directory, self.token = directory, token
        self.known = {root['pid']: root}
        self.groups = {root['pgid']}
        self.registered, self.conflicts = set(), set()
        self.unresolved = set()
        self.term, self.kill = 0, 0
        self.signalled = {signal.SIGTERM: set(), signal.SIGKILL: set()}

    def refresh(self, acknowledge=True):
        rows = table()
        current = {}
        for pid, old in list(self.known.items()):
            value = identity(pid)
            if value is not None and not same(old, value):
                self.conflicts.add(pid)
            elif value is not None and value['live']:
                current[pid] = value
        files = list(self.directory.glob('*.json'))
        require(len(files) <= 64)
        for path in files:
            row = read_private(path)
            require(set(row) == {'pid','ppid','pgid','uid','start','token'} and row['token'] == self.token)
            require(all(type(row[k]) is int for k in ('pid','ppid','pgid','uid')) and type(row['start']) is str and len(row['start']) <= 80)
            require(path.name == str(row['pid'])+'.json' and row['pid'] == row['pgid'] and row['pgid'] != os.getpgrp() and row['uid'] == os.getuid())
            if row['pid'] in self.registered:
                continue
            value = identity(row['pid'])
            if value is None:
                continue
            require(same(row, value))
            parent, visited = row['ppid'], set()
            while parent not in current and parent in rows and parent not in visited:
                visited.add(parent); parent = rows[parent][0]
            require(parent in current)
            self.known[row['pid']] = value; current[row['pid']] = value
            self.groups.add(row['pgid']); self.registered.add(row['pid'])
            if acknowledge and not (self.directory/'closed').exists():
                write_private(self.directory/(str(row['pid'])+'.ack'), {'token': self.token})
        # A live previously identified group member anchors its group. New detached
        # descendants are admitted only while their exact parent is still owned.
        changed = True
        while changed:
            changed = False
            anchors = {r['pgid'] for r in current.values()}
            for pid, (parent, group) in rows.items():
                if pid <= 1 or pid in self.known or (parent not in current and group not in anchors):
                    continue
                value = identity(pid)
                if value is None or not value['live']:
                    continue
                # Reject a stale process-table relationship rather than adopting
                # a reused PID or a child that moved to a different group.
                require(value['ppid'] == parent and value['pgid'] == group)
                require(value['uid'] == os.getuid() and value['pgid'] != os.getpgrp())
                self.known[pid] = value; current[pid] = value; self.groups.add(value['pgid'])
                require(len(self.known) <= MAX_PROCESSES)
                changed = True
        self.unresolved = {group for _, group in rows.values() if group in self.groups and not any(r['pgid'] == group for r in current.values())}
        # Known zombies are terminated, not live survivors; exclude their groups.
        self.unresolved = {g for g in self.unresolved if any(pid not in self.known for pid,(_,group) in rows.items() if group == g)}
        return current

    def observed_known(self):
        current = {}
        for pid, old in self.known.items():
            value = identity(pid)
            if value is not None and not same(old, value):
                self.conflicts.add(pid)
            elif value is not None and value['live']:
                current[pid] = value
        return current

    def signal_owned(self, current, number):
        sent_groups = set()
        for pid, previous in sorted(current.items()):
            value = identity(pid)
            if value is None or not value['live']:
                continue
            if not same(previous, value):
                self.conflicts.add(pid); continue
            require(value['pgid'] != os.getpgrp() and value['uid'] == os.getuid())
            key = (pid, value['start'])
            if key in self.signalled[number]:
                continue
            try:
                if pid == value['pgid']:
                    os.killpg(pid, number); sent_groups.add(pid)
                elif value['pgid'] not in sent_groups:
                    os.kill(pid, number)
                else:
                    self.signalled[number].add(key)
                    continue
                self.signalled[number].add(key)
                if number == signal.SIGTERM: self.term += 1
                else: self.kill += 1
            except ProcessLookupError:
                pass

    def close(self, process, trigger):
        write_private(self.directory/'closed', {'closed': True})
        end, kill_at = time.monotonic()+10, time.monotonic()+2
        observation_failed = False
        while True:
            process.poll()
            try:
                current = self.refresh(False)
            except Exception:
                # Metadata failure refuses qualification but must still attempt
                # exact-identity cleanup of every already admitted process.
                observation_failed = True
                current = self.observed_known()
            self.signal_owned(current, signal.SIGKILL if time.monotonic() >= kill_at else signal.SIGTERM)
            if not current or time.monotonic() >= end:
                break
            time.sleep(.05)
        process.poll()
        current = self.observed_known()
        ok = not current and not self.conflicts and not self.unresolved and not observation_failed
        return {'schema_version':1,'scope':'registered-posix-groups-and-observed-descendants','result':'PASS' if ok else 'FAIL',
            'trigger':trigger,'registeredBrowserGroups':len(self.registered),'trackedProcesses':len(self.known),
            'termSignals':self.term,'killSignals':self.kill,'remainingLive':len(current),'identityConflicts':len(self.conflicts),
            'unresolvedGroups':max(len(self.unresolved), int(observation_failed)),'registryClosed':True}


class BrowserCommandFailure(RuntimeError):
    def __init__(self, proof):
        super().__init__('Bounded owned browser command failed; private cleanup proof retained')
        self.proof = proof


def run(args, *, cwd, folder, executable, expected_hash, deadline, admit, timeout=300):
    require(os.name == 'posix' and sys.platform in ('darwin','linux'))
    require(digest(executable) == expected_hash)
    folder.mkdir(mode=0o700)
    registry = folder/'registry'; registry.mkdir(mode=0o700)
    token = secrets.token_hex(32)
    control = folder/'control.json'
    write_private(control, {'version':1,'token':token,'executable':str(executable),'sha256':expected_hash})
    env = {**os.environ, 'GC_PROTECTED_BROWSER_CONTROL':str(control)}
    admit()
    # Selector construction happens before any child exists.
    poll = selectors.DefaultSelector()
    try:
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--command-gate', *args],
            cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except BaseException:
        poll.close()
        raise
    tracker = None
    data = {'stdout':bytearray(),'stderr':bytearray()}
    end, failure, trigger = min(deadline, time.monotonic()+timeout), None, 'normal'
    interrupted = [False]
    def stop(_number, _frame): interrupted[0] = True
    handlers = {}
    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, stop)
        tracker = Tracker(identity(process.pid), registry, token)
        poll.register(process.stdout, selectors.EVENT_READ, 'stdout'); poll.register(process.stderr, selectors.EVENT_READ, 'stderr')
        write_private(folder/'command.ack',{'token':token})
        while poll.get_map() or process.poll() is None:
            if time.monotonic() >= end:
                trigger = 'timeout'; raise RuntimeError()
            require(not interrupted[0])
            admit(); tracker.refresh()
            for key,_ in poll.select(.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    poll.unregister(key.fileobj); continue
                require(sum(map(len,data.values()))+len(chunk) <= CAP)
                data[key.data].extend(chunk)
        if process.returncode != 0: trigger = 'nonzero'
    except BaseException as error:
        failure = error
        if trigger != 'timeout': trigger = 'exception'
    finally:
        poll.close()
        try:
            if tracker is None:
                # No ack was written and this direct Popen child has never been
                # polled/waited: its PID cannot be reused before wait/reap. The
                # gate cannot create descendants or change its session/group.
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=3)
                proof = {'schema_version':1,'scope':'registered-posix-groups-and-observed-descendants','result':'FAIL','trigger':trigger,
                    'registeredBrowserGroups':0,'trackedProcesses':1,'termSignals':0,'killSignals':1,'remainingLive':0,
                    'identityConflicts':0,'unresolvedGroups':1,'registryClosed':True}
                write_private(registry/'closed',{'closed':True})
            else:
                proof = tracker.close(process, trigger)
        except BaseException:
            # Never turn an incomplete observation into a cleanup success.
            proof = {'schema_version':1,'scope':'registered-posix-groups-and-observed-descendants','result':'FAIL','trigger':trigger,
                'registeredBrowserGroups':len(tracker.registered) if tracker else 0,'trackedProcesses':len(tracker.known) if tracker else 0,'termSignals':tracker.term if tracker else 0,
                'killSignals':tracker.kill if tracker else 0,'remainingLive':len(tracker.known) if tracker else 1,'identityConflicts':len(tracker.conflicts) if tracker else 0,
                'unresolvedGroups':max(1,len(tracker.unresolved)) if tracker else 1,'registryClosed':(registry/'closed').exists()}
        process.stdout.close(); process.stderr.close()
        for number, handler in handlers.items(): signal.signal(number, handler)
    if failure is not None or proof['result'] != 'PASS':
        raise BrowserCommandFailure(proof)
    return subprocess.CompletedProcess([],process.returncode,data['stdout'].decode(errors='replace'),data['stderr'].decode(errors='replace')),proof


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] == '--command-gate': command_gate()
        else: launcher()
    except BaseException:
        print('OWNED_BROWSER_LAUNCH_REFUSED',file=sys.stderr)
        raise SystemExit(1)
