# SPDX-License-Identifier: Apache-2.0
"""One process-wide POSIX wall deadline for the synchronous main-thread worker.

This guard requires an unused, unblocked SIGALRM/ITIMER_REAL facility. It never
replaces another active alarm. Trusted scan code must not suppress ScanFailure;
OS tasks stuck in uninterruptible kernel/native code need an outer process limit.
"""
from contextlib import contextmanager
import math
import signal
import threading
import time

from .postgresql import ScanFailure


def unavailable():
    raise ScanFailure("SOURCE_DEADLINE_UNAVAILABLE")


@contextmanager
def deadline(seconds):
    try:
        valid_duration = type(seconds) in (int, float) and math.isfinite(seconds) and seconds > 0
    except (OverflowError, ValueError):
        valid_duration = False
    if (not valid_duration or threading.current_thread() is not threading.main_thread()
            or any(not hasattr(signal, name) for name in (
                "SIGALRM", "ITIMER_REAL", "pthread_sigmask", "sigpending", "sigwait", "getitimer", "setitimer"))):
        unavailable()

    alarm = signal.SIGALRM
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {alarm})
    installed = False
    previous_handler = None

    def restore():
        nonlocal installed
        if installed:
            # Stop and consume only our pending alarm before restoring its prior
            # handler. Otherwise teardown could deliver our expiry to SIG_DFL.
            signal.pthread_sigmask(signal.SIG_BLOCK, {alarm})
            signal.setitimer(signal.ITIMER_REAL, 0)
            if alarm in signal.sigpending():
                signal.sigwait({alarm})
            signal.signal(alarm, previous_handler)
            installed = False
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def expired(_signum, _frame):
        # Expiry can land at the first cleanup bytecodes, before its mask call.
        # Restore here as well so an exception cannot interrupt restoration.
        restore()
        raise ScanFailure("SOURCE_DEADLINE_EXCEEDED")

    try:
        # Inspect while blocked, so an already-expired pending alarm is never
        # mistaken for an unused timer and attributed to this scan.
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        if alarm in previous_mask or alarm in signal.sigpending() or any(previous_timer):
            unavailable()
        previous_handler = signal.getsignal(alarm)
        signal.signal(alarm, expired)
        installed = True
        expires_at = time.monotonic() + seconds
        try:
            signal.setitimer(signal.ITIMER_REAL, seconds)
        except (OverflowError, OSError, ValueError):
            unavailable()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        yield
        # A caller cannot turn a caught expiry into a successful scan result.
        if time.monotonic() >= expires_at:
            expired(None, None)
    finally:
        # The admitted prior timer was exactly inactive; it remains inactive.
        restore()
