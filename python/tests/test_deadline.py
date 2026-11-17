# SPDX-License-Identifier: Apache-2.0
"""Real POSIX timer and blocking-I/O tests; no source/network/cloud qualification."""
from concurrent.futures import ThreadPoolExecutor
import os
import signal
import socket
import threading
import time
import unittest
from unittest.mock import patch

from governance_workers.deadline import deadline
from governance_workers.postgresql import ScanFailure


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        self.previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertNotIn(signal.SIGALRM, self.previous_mask)
        self.observed = []
        self.handler = lambda signum, frame: self.observed.append(signum)
        signal.signal(signal.SIGALRM, self.handler)
        self.addCleanup(self.restore)

    def restore(self):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        signal.setitimer(signal.ITIMER_REAL, 0)
        if signal.SIGALRM in signal.sigpending(): signal.sigwait({signal.SIGALRM})
        signal.signal(signal.SIGALRM, self.previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)

    def assert_restored(self):
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), self.previous_mask)
        self.assertEqual(self.observed, [])

    def test_success_restores_handler_timer_and_mask(self):
        with deadline(1): self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        self.assert_restored()
        time.sleep(.02)
        self.assertEqual(self.observed, [])

    def test_body_error_restores_state_without_replacing_error(self):
        with self.assertRaisesRegex(ValueError, '^synthetic-body-error$'):
            with deadline(1): raise ValueError('synthetic-body-error')
        self.assert_restored()

    def test_actual_blocking_sleep_is_interrupted(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_EXCEEDED$'):
            with deadline(.04): time.sleep(2)
        self.assertLess(time.monotonic()-started, .8)
        self.assert_restored()

    def test_actual_blocking_socket_read_is_interrupted_without_socket_timeout(self):
        left, right = socket.socketpair()
        try:
            self.assertIsNone(left.gettimeout())
            started = time.monotonic()
            with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_EXCEEDED$'):
                with deadline(.04): left.recv(1)
            self.assertLess(time.monotonic()-started, .8)
        finally:
            left.close(); right.close()
        self.assert_restored()

    def test_actual_python_normalization_work_is_interrupted(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_EXCEEDED$'):
            with deadline(.04):
                while True: sum(range(100))
        self.assertLess(time.monotonic()-started, .8)
        self.assert_restored()

    def test_active_prior_alarm_is_not_replaced_or_renewed(self):
        signal.setitimer(signal.ITIMER_REAL, 2, 3)
        before = signal.getitimer(signal.ITIMER_REAL)
        entered = False
        with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_UNAVAILABLE$'):
            with deadline(.01): entered = True
        after = signal.getitimer(signal.ITIMER_REAL)
        self.assertFalse(entered)
        self.assertGreater(after[0], 1)
        self.assertLessEqual(after[0], before[0])
        self.assertEqual(after[1], before[1])
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)
        signal.setitimer(signal.ITIMER_REAL, 0)
        self.assert_restored()

    def test_nested_deadline_refuses_and_outer_original_timer_still_expires(self):
        with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_EXCEEDED$'):
            with deadline(.04):
                outer = signal.getsignal(signal.SIGALRM)
                with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_UNAVAILABLE$'):
                    with deadline(10): self.fail('Nested deadline entered')
                self.assertIs(signal.getsignal(signal.SIGALRM), outer)
                time.sleep(2)
        self.assert_restored()

    def test_non_main_thread_refuses_without_changing_process_state(self):
        def run():
            self.assertIsNot(threading.current_thread(), threading.main_thread())
            with deadline(1): return 'unexpected'
        with ThreadPoolExecutor(max_workers=1) as executor:
            with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_UNAVAILABLE$'):
                executor.submit(run).result(timeout=1)
        self.assert_restored()

    def test_invalid_durations_refuse_without_installing_handler(self):
        for value in (True, None, '1', 0, -1, float('inf'), float('nan'), 1e300, 10**1000):
            with self.subTest(value=value), self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_UNAVAILABLE$'):
                with deadline(value): self.fail('Invalid deadline entered')
            self.assert_restored()

    def test_blocked_alarm_refuses_and_preserves_original_mask(self):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_UNAVAILABLE$'):
            with deadline(1): self.fail('Blocked alarm entered')
        self.assertIn(signal.SIGALRM, signal.pthread_sigmask(signal.SIG_BLOCK, set()))
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
        self.assert_restored()

    def test_expiry_at_cleanup_boundary_still_restores_predecessor(self):
        original = signal.pthread_sigmask
        blocks = 0
        def inject_at_cleanup(how, mask):
            nonlocal blocks
            if how == signal.SIG_BLOCK and mask == {signal.SIGALRM}:
                blocks += 1
                if blocks == 2: os.kill(os.getpid(), signal.SIGALRM)
            return original(how, mask)
        with patch('governance_workers.deadline.signal.pthread_sigmask', side_effect=inject_at_cleanup):
            with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_EXCEEDED$'):
                with deadline(1): pass
        self.assertGreaterEqual(blocks, 3)
        self.assert_restored()

    def test_caught_expiry_cannot_be_returned_as_success(self):
        with self.assertRaisesRegex(ScanFailure, '^SOURCE_DEADLINE_EXCEEDED$'):
            with deadline(.02):
                try: time.sleep(2)
                except ScanFailure: pass
        self.assert_restored()


if __name__=='__main__': unittest.main()
