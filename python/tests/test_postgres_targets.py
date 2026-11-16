# SPDX-License-Identifier: Apache-2.0
"""Policy, filesystem and real subprocess checks; no database/TLS-server claim."""
from dataclasses import FrozenInstanceError
import ipaddress
import json
import os
from pathlib import Path
import socket
import signal
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from psycopg.conninfo import conninfo_to_dict, make_conninfo
from governance_workers import postgres_targets as targets
from governance_workers.deadline import deadline
from governance_workers.postgresql import ScanFailure

# Synthetic public CA only. Its temporary generation key was discarded.
CA = """-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUTBuXbjOQ6flnNwghy25Dtb70dTswDQYJKoZIhvcNAQEL
BQAwNjE0MDIGA1UEAwwrR292ZXJuYW5jZSBDb21tb25zIFN5bnRoZXRpYyBUYXJn
ZXQgVGVzdCBDQTAeFw0yNjExMTYxMzE1MTJaFw0zNjExMTMxMzE1MTJaMDYxNDAy
BgNVBAMMK0dvdmVybmFuY2UgQ29tbW9ucyBTeW50aGV0aWMgVGFyZ2V0IFRlc3Qg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTBpeyGO0BmCkjf0Cr
FQQdyLhWvgylEgsC/gDCNZgoY3cpCX9Bqgi+e2TyUqs/lMHZS+sWWlxvikIpFb0l
DRJl1lTnfd7NkEj7O2VZ5aNyowDMilCT9oihBDS5ChEPCSD4YlVvf5YwJNFGonjS
2zyYtEHvOnEXv6ngafsgLk3CBscHgtSA45qUS92+efVDiRnK4wsYRuBM2qGYKvZY
OdVnjBuLCqTdm/1IkQyQvlselWnHf2HTd5zTmMKtCGxx6l+YNlSS8EpPwIFwcW6b
ATRY7xx1MvHK1qkRinA5PwSlrE51tMUwl3jIt7/NmrzI68jniKLlTvuCHKBiQ25C
1MqRAgMBAAGjUzBRMB0GA1UdDgQWBBTBNM70XUwmYxFQkv/22aBkplMhvDAfBgNV
HSMEGDAWgBTBNM70XUwmYxFQkv/22aBkplMhvDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQBa/n9Uxy2yIEc31FNlpaXrsHUUe002ZeN+/Zb82qk1
cG62YCrrXxQw9jJ5C8FOLfuc9Onnw7bTkDwMFLdr03TJEkpEN4lR87EcWFbSHWTP
ZAlSkBjF3Eq+TRuR0WizRylu6XHgCt8SagzLxZxuJZ/AW7xFACVzo4XTzPkQ51B0
8/ugcQwTgDN5j6UVVa9DvMe14L2Yj1mExspyJXwtC0lLXaNrk7RUXdvGEpu5P84N
0p0Z6jBIXZ2T10YBBiJmrjOKIOx7HNTRTtNqmqRkoVCbxvboQAGgiEVCA5NKdAFO
SdnImXvKi10pPMGkDDQRKCB5aeBu9wHtYVtkPDqLxy4N
-----END CERTIFICATE-----
"""


def document():
    return {"formatVersion": 1, "targets": {"warehouse": {
        "tenantIds": ["tenant-one"], "host": "db.example.test", "port": 5432,
        "database": "analytics", "schema": "catalog", "allowedCidrs": ["10.8.0.0/16"],
        "tls": {"mode": "verify-full", "caPem": CA},
    }}}


def source():
    return {"connectorId": "postgresql", "secretRef": "warehouse", "host": "db.example.test",
            "port": 5432, "database": "analytics", "schema": "catalog"}


def secret():
    return {"connectorId": "postgresql", "tenantIds": ["tenant-one"], "host": "db.example.test",
            "port": 5432, "database": "analytics", "schema": "catalog",
            "username": "metadata_reader", "password": "synthetic-test-password"}


class Cases(unittest.TestCase):
    def assert_code(self, code, call):
        with self.assertRaises(targets.TargetPolicyError) as error:
            call()
        self.assertEqual(error.exception.code, code)
        self.assertEqual(str(error.exception), code)
        return error.exception

    def parse(self, value=None):
        return targets.parse_policy(json.dumps(value if value is not None else document()))


class ParserTests(Cases):
    def test_complete_policy_is_deeply_immutable(self):
        policy = self.parse()
        entry = policy.targets["warehouse"]
        with self.assertRaises(TypeError):
            policy.targets["warehouse"] = entry
        with self.assertRaises(FrozenInstanceError):
            entry.host = "attacker.test"
        with self.assertRaises(AttributeError):
            entry.tenant_ids.add("other")
        self.assertEqual(entry.allowed_cidrs, (ipaddress.ip_network("10.8.0.0/16"),))
        self.assertEqual(self.parse({"formatVersion": 1, "targets": {}}).targets, {})

    def test_closed_shapes_and_no_plaintext_or_path_configuration(self):
        for mutate in (
            lambda x: x.update(extra=True),
            lambda x: x.update(formatVersion=True),
            lambda x: x["targets"]["warehouse"].update(extra=True),
            lambda x: x["targets"]["warehouse"]["tls"].update(mode="require"),
            lambda x: x["targets"]["warehouse"]["tls"].update(caFile="/tmp/ca.pem"),
        ):
            value = document()
            mutate(value)
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: self.parse(value))

    def test_duplicate_keys_nonfinite_and_malformed_unicode(self):
        valid = json.dumps(document())
        samples = [valid.replace('"formatVersion": 1', '"formatVersion": 1, "formatVersion": 1'),
                   valid.replace('"port": 5432', '"port": NaN'), valid.replace('"port": 5432', '"port": Infinity'),
                   valid.replace("catalog", r"\ud800"), valid.replace("catalog", r"\u0000"), b"\xff"]
        for sample in samples:
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: targets.parse_policy(sample))

    def test_byte_depth_and_collection_limits(self):
        for sample in (b" " * (targets.MAX_BYTES + 1), "[" * 9 + "]" * 9):
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: targets.parse_policy(sample))
        for key, value in (("tenantIds", []), ("tenantIds", ["tenant-one"] * 2),
                           ("tenantIds", [str(i) for i in range(257)]),
                           ("allowedCidrs", []), ("allowedCidrs", ["10.8.0.0/16"] * 2),
                           ("allowedCidrs", ["10.8.0.1/16"]), ("port", True), ("port", 65536)):
            doc = document()
            doc["targets"]["warehouse"][key] = value
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: self.parse(doc))

    def test_target_strings_cannot_be_sockets_lists_dsns_or_ambiguous_ips(self):
        for host in ("/tmp/pg", "db.one,db.two", "DB.TEST", "db.test.", "127.01.1.1", "2130706433", "0x7f000001", "0x7f.0.0.1",
                     "host:5432", "[::1]", "fe80::1%lo0", "db\x7f.test", "db\ud800.test"):
            doc = document()
            doc["targets"]["warehouse"]["host"] = host
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: self.parse(doc))
        for db in ("host=evil.test dbname=x", "postgresql://evil.test/db", "POSTGRESQL://evil.test/db",
                   "Postgres://evil.test/db", "a\x7fb", "x" * 64, "é" * 32):
            doc = document()
            doc["targets"]["warehouse"]["database"] = db
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: self.parse(doc))

    def test_ca_must_be_certificate_material_not_key_or_ambient_system_roots(self):
        for pem in ("system", "/etc/ssl/cert.pem", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                    CA + "garbage", CA.replace("MIIDTT", "!!!!!!"), CA + CA, "x" * 65537):
            doc = document()
            doc["targets"]["warehouse"]["tls"]["caPem"] = pem
            self.assert_code("SOURCE_TARGET_POLICY_INVALID", lambda: self.parse(doc))


class FileTests(Cases):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.path = self.directory / "targets.json"
        self.path.write_text(json.dumps(document()))
        self.path.chmod(0o600)

    def test_atomic_replacement_is_reloaded_and_previous_snapshot_unchanged(self):
        first = targets.load_policy(self.path)
        changed = document()
        changed["targets"]["warehouse"]["tenantIds"] = ["tenant-two"]
        replacement = self.directory / "replacement"
        replacement.write_text(json.dumps(changed))
        replacement.chmod(0o400)
        replacement.replace(self.path)
        second = targets.load_policy(self.path)
        self.assertEqual(first.targets["warehouse"].tenant_ids, {"tenant-one"})
        self.assertEqual(second.targets["warehouse"].tenant_ids, {"tenant-two"})
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o400)

    def test_symlinks_final_or_parent_and_hardlinks_are_refused(self):
        link = self.directory / "link"
        link.symlink_to(self.path)
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(link))
        parent_link = self.directory / "linked-directory"
        parent_link.symlink_to(self.directory, target_is_directory=True)
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(parent_link / "targets.json"))
        os.link(self.path, self.directory / "hardlink")
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(self.path))

    def test_permissions_type_size_and_missing_fail_without_chmod(self):
        for mode in (0o644, 0o640, 0o660, 0o700):
            self.path.chmod(mode)
            self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(self.path))
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), mode)
        self.path.chmod(0o600)
        self.path.write_bytes(b"x" * (targets.MAX_BYTES + 1))
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(self.path))
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(self.directory))
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(self.directory / "missing"))
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(fifo))

    def test_in_place_write_during_read_is_detected(self):
        original_read = os.read
        changed = False

        def read(fd, count):
            nonlocal changed
            data = original_read(fd, count)
            if not changed:
                changed = True
                self.path.write_bytes(self.path.read_bytes().replace(b"tenant-one", b"tenant-two"))
            return data

        with patch.object(targets.os, "read", side_effect=read):
            self.assert_code("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: targets.load_policy(self.path))


class DnsTests(Cases):
    def test_real_numeric_lookup_and_all_address_admission(self):
        rows = targets._resolve("10.8.0.4", 5432, time.monotonic() + 3)
        self.assertEqual(rows, (ipaddress.ip_address("10.8.0.4"),))
        target = self.parse().targets["warehouse"]
        targets._address_allowed(rows[0], target)
        self.assert_code("SOURCE_DESTINATION_DENIED", lambda: targets._address_allowed(ipaddress.ip_address("10.9.0.4"), target))

    def test_blocked_ranges_override_allow_all_ipv4_and_ipv6(self):
        doc = document()
        doc["targets"]["warehouse"]["allowedCidrs"] = ["0.0.0.0/0", "::/0"]
        target = self.parse(doc).targets["warehouse"]
        for text in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.169.254", "168.63.129.16",
                     "100.100.100.200", "100.64.1.1", "192.0.2.5", "240.0.0.1", "::", "::1", "fe80::1",
                     "ff02::1", "fd00:ec2::254", "fd20:ce::254", "::ffff:10.8.0.4", "2002:0a08:0004::1", "2001:db8::1",
                     "fec0::1", "64:ff9b::a9fe:a9fe"):
            with self.subTest(address=text):
                self.assert_code("SOURCE_DESTINATION_DENIED", lambda: targets._address_allowed(ipaddress.ip_address(text), target))
        for text in ("10.8.0.4", "172.16.1.2", "192.168.1.2", "fd12::1", "8.8.8.8", "2606:4700:4700::1111"):
            targets._address_allowed(ipaddress.ip_address(text), target)

    def test_real_subprocess_timeout_is_killed_and_reaped(self):
        children = []
        popen = subprocess.Popen

        def capture(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        started = time.monotonic()
        with patch.object(targets, "_DNS_SCRIPT", "import time; time.sleep(30)"), patch.object(targets.subprocess, "Popen", side_effect=capture):
            self.assert_code("SOURCE_DEADLINE_EXCEEDED", lambda: targets._resolve("db.example.test", 5432, started + .1))
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(len(children), 1)
        self.assertLess(children[0].returncode, 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)
        self.assertTrue(children[0].stdout.closed)

    def test_outer_scan_alarm_also_kills_and_reaps_dns(self):
        children = []
        popen = subprocess.Popen

        def capture(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(targets, "_DNS_SCRIPT", "import time; time.sleep(30)"), patch.object(targets.subprocess, "Popen", side_effect=capture):
            with self.assertRaises(ScanFailure) as error:
                with deadline(.1):
                    targets._resolve("db.example.test", 5432, time.monotonic() + 30)
        self.assertEqual(error.exception.code, "SOURCE_DEADLINE_EXCEEDED")
        self.assertEqual(len(children), 1)
        self.assertLess(children[0].returncode, 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)
        self.assertTrue(children[0].stdout.closed)

    def test_slot_exhaustion_does_not_spawn_or_extend_deadline(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with patch.object(targets, "_DNS_SLOTS", slots), patch.object(targets.subprocess, "Popen") as popen:
            self.assert_code("SOURCE_TRANSPORT_ERROR", lambda: targets._resolve("db.example.test", 5432, time.monotonic() + 2))
            popen.assert_not_called()
        slots.release()
        with patch.object(targets.subprocess, "Popen") as popen:
            self.assert_code("SOURCE_DEADLINE_EXCEEDED", lambda: targets._resolve("db.example.test", 5432, time.monotonic() - 1))
            popen.assert_not_called()

    def test_malformed_or_excess_child_results_are_refused(self):
        invalid = [[], [[socket.AF_INET, "10.8.0.4", 5432]] * 17,
                   [[socket.AF_INET, "10.8.0.4", 5433]], [[socket.AF_INET6, "10.8.0.4", 5432]],
                   [[socket.AF_INET6, "fe80::1%lo0", 5432]], [[socket.AF_INET, "10.8.0.4", True]]]
        for result in invalid:
            script = "import sys;sys.stdout.write(" + repr(json.dumps(result)) + ")"
            with patch.object(targets, "_DNS_SCRIPT", script):
                self.assert_code("SOURCE_DESTINATION_DENIED", lambda: targets._resolve("db.example.test", 5432, time.monotonic() + 3))


class ConnectionTests(Cases):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.policy = self.parse()
        self.resolver = patch.object(targets, "_resolve", return_value=(ipaddress.ip_address("10.8.0.4"),))
        self.resolve = self.resolver.start()
        self.addCleanup(self.resolver.stop)

    def enter(self, source_value=None, secret_value=None, tenant="tenant-one", **kwargs):
        return targets.prepare_connection(self.policy, source_value if source_value is not None else source(),
                                          secret_value if secret_value is not None else secret(), tenant,
                                          deadline_at=kwargs.get("deadline_at", time.monotonic() + 10))

    def consume(self, **kwargs):
        with self.enter(**kwargs):
            pass

    def test_exact_scope_and_ref_denial_occurs_before_dns(self):
        for change in ({"host": "other.test"}, {"port": True}, {"port": 5433}, {"database": "other"},
                       {"schema": "other"}, {"secretRef": "missing"}, {"connectorId": "unity-catalog"}):
            self.assert_code("SOURCE_TARGET_DENIED", lambda: self.consume(source_value=dict(source(), **change)))
        for change in ({"host": "other.test"}, {"database": "other"}, {"secretRef": "other"},
                       {"tenantIds": "tenant-one"}, {"connectorId": "unity-catalog"}, {"password": "\ud800"}):
            self.assert_code("SOURCE_TARGET_DENIED", lambda: self.consume(secret_value=dict(secret(), **change)))
        self.assert_code("SOURCE_SCOPE_DENIED", lambda: self.consume(tenant="tenant-two"))
        self.assert_code("SOURCE_SCOPE_DENIED", lambda: self.consume(secret_value=dict(secret(), tenantIds=["tenant-two"])))
        self.resolve.assert_not_called()

    def test_any_unapproved_dns_answer_rejects_entire_target(self):
        self.resolve.return_value = (ipaddress.ip_address("10.8.0.4"), ipaddress.ip_address("169.254.169.254"))
        self.assert_code("SOURCE_DESTINATION_DENIED", self.consume)

    def test_parameters_pin_dns_and_enforce_tls_without_ambient_files(self):
        with self.enter() as params:
            self.assertEqual(params["host"], "db.example.test")
            self.assertEqual(params["hostaddr"], "10.8.0.4")
            self.assertEqual(params["sslmode"], "verify-full")
            self.assertEqual(params["ssl_min_protocol_version"], "TLSv1.2")
            self.assertEqual(params["sslcertmode"], "disable")
            self.assertEqual(params["gssencmode"], "disable")
            self.assertEqual(params["gssdelegation"], "0")
            self.assertEqual(params["require_auth"], "scram-sha-256,md5,password")
            self.assertEqual(params["options"], "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000")
            self.assertEqual(params["passfile"], os.devnull)
            ca = Path(params["sslrootcert"])
            self.assertEqual(ca.read_text(), CA)
            self.assertEqual(stat.S_IMODE(ca.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(ca.parent.stat().st_mode), 0o700)
            self.assertEqual(ca.stat().st_uid, os.geteuid())
            for name in ("sslcert", "sslkey", "sslcrl"):
                self.assertEqual(Path(params[name]).parent, ca.parent)
                self.assertFalse(Path(params[name]).exists())
            self.assertEqual(list(Path(params["sslcrldir"]).iterdir()), [])
            self.assertNotIn(secret()["password"], repr(params))
            self.assertNotIn(secret()["username"], repr(params))
            with self.assertRaises(TypeError):
                params["hostaddr"] = "127.0.0.1"
            # Actual pinned libpq parser accepts the full parameters, preserving
            # database/user/password as scalar values, not DSN interpolation.
            parsed = conninfo_to_dict(make_conninfo(**params))
            self.assertEqual(parsed["hostaddr"], "10.8.0.4")
            self.assertEqual(parsed["sslcertmode"], "disable")
        self.assertFalse(ca.parent.exists())
        self.resolve.assert_called_once()

    def test_ca_removed_on_caller_failure_and_exception_preserved(self):
        problem = RuntimeError("synthetic caller failure")
        with self.assertRaises(RuntimeError) as error:
            with self.enter() as params:
                directory = Path(params["sslrootcert"]).parent
                raise problem
        self.assertIs(error.exception, problem)
        self.assertFalse(directory.exists())

    def test_all_pg_and_tls_environment_including_empty_values_fail_closed(self):
        for key in ("PGHOST", "PGOPTIONS", "PGSERVICE", "PGPASSFILE", "PGSSLMODE", "PGFUTUREOPTION",
                    "OPENSSL_CONF", "OPENSSL_MODULES", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
            with patch.dict(os.environ, {key: ""}):
                self.assert_code("SOURCE_CONNECTION_ENVIRONMENT_DENIED", self.consume)
        self.resolve.assert_not_called()

    def test_old_libpq_refused_without_silent_option_fallback(self):
        with patch.object(targets, "_libpq_version", return_value=160000):
            self.assert_code("SOURCE_TLS_UNAVAILABLE", self.consume)
        self.resolve.assert_not_called()

    def test_deadline_not_renewed_after_dns_or_context_body(self):
        self.assert_code("SOURCE_DEADLINE_EXCEEDED", lambda: self.consume(deadline_at=time.monotonic() + 1))
        expires = time.monotonic() + 5
        manager = self.enter(deadline_at=expires)
        params = manager.__enter__()
        directory = Path(params["sslrootcert"]).parent
        with patch.object(targets.time, "monotonic", return_value=expires + 1):
            self.assert_code("SOURCE_DEADLINE_EXCEEDED", lambda: manager.__exit__(None, None, None))
        self.assertFalse(directory.exists())

    def test_invalid_deadline_is_a_safe_error(self):
        for value in (True, "30", float("inf"), float("nan"), 10 ** 1000):
            self.assert_code("SOURCE_DEADLINE_UNAVAILABLE", lambda: self.consume(deadline_at=value))
        self.resolve.assert_not_called()


class AlarmOwnershipTests(Cases):
    def assert_alarm_cleanup(self, call):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        with self.assertRaises(ScanFailure) as error:
            with deadline(3):
                call()
        self.assertEqual(error.exception.code, "SOURCE_DEADLINE_EXCEEDED")
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_alarm_after_real_spawn_before_assignment_reaps_exact_child(self):
        original = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            signal.raise_signal(signal.SIGALRM)
            return child

        with patch.object(targets, "_DNS_SCRIPT", "import time;time.sleep(30)"), patch.object(targets.subprocess, "Popen", side_effect=spawn):
            self.assert_alarm_cleanup(lambda: targets._resolve("db.example.test", 5432, time.monotonic() + 3))
        self.assertEqual(len(children), 1)
        self.assertLess(children[0].returncode, 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)
        self.assertTrue(children[0].stdout.closed)

    def test_alarm_at_dns_cleanup_entry_reaps_and_preserves_mask(self):
        original_exit, original_popen = targets._Resources.__exit__, subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child

        def exit_now(self, *args):
            signal.raise_signal(signal.SIGALRM)
            return original_exit(self, *args)

        with patch.object(targets._Resources, "__exit__", exit_now), patch.object(targets.subprocess, "Popen", side_effect=spawn):
            self.assert_alarm_cleanup(lambda: targets._resolve("10.8.0.4", 5432, time.monotonic() + 3))
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    def test_alarm_after_slot_acquisition_releases_slot_without_spawning(self):
        slots = threading.BoundedSemaphore(1)

        class AlarmSlot:
            def acquire(self, **kwargs):
                result = slots.acquire(**kwargs)
                signal.raise_signal(signal.SIGALRM)
                return result

            def release(self):
                slots.release()

        with patch.object(targets, "_DNS_SLOTS", AlarmSlot()), patch.object(targets.subprocess, "Popen") as popen:
            self.assert_alarm_cleanup(lambda: targets._resolve("db.example.test", 5432, time.monotonic() + 3))
            popen.assert_not_called()
        self.assertTrue(slots.acquire(blocking=False))
        slots.release()

    def test_alarm_after_fd_open_before_assignment_closes_exact_descriptor(self):
        original = os.open
        opened = []

        def open_file(*args, **kwargs):
            fd = original(*args, **kwargs)
            opened.append(fd)
            signal.raise_signal(signal.SIGALRM)
            return fd

        with patch.object(targets.os, "open", side_effect=open_file):
            self.assert_alarm_cleanup(lambda: targets.load_policy("/unused-after-first-open"))
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_alarm_after_directory_creation_before_assignment_removes_it(self):
        original = tempfile.mkdtemp
        created = []

        def make_dir(*args, **kwargs):
            path = original(*args, **kwargs)
            created.append(Path(path))
            signal.raise_signal(signal.SIGALRM)
            return path

        def use():
            with targets.prepare_connection(self.parse(), source(), secret(), "tenant-one", deadline_at=time.monotonic() + 3):
                self.fail("expiry must refuse before yielding credentials")

        with patch.dict(os.environ, {}, clear=True), patch.object(targets, "_resolve", return_value=(ipaddress.ip_address("10.8.0.4"),)), patch.object(targets.tempfile, "mkdtemp", side_effect=make_dir):
            self.assert_alarm_cleanup(use)
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def test_alarm_at_ca_cleanup_entry_removes_private_material(self):
        original = targets._Resources.__exit__
        directories = []

        def exit_now(self, *args):
            signal.raise_signal(signal.SIGALRM)
            return original(self, *args)

        def use():
            with targets.prepare_connection(self.parse(), source(), secret(), "tenant-one", deadline_at=time.monotonic() + 3) as params:
                directories.append(Path(params["sslrootcert"]).parent)

        with patch.dict(os.environ, {}, clear=True), patch.object(targets, "_resolve", return_value=(ipaddress.ip_address("10.8.0.4"),)), patch.object(targets._Resources, "__exit__", exit_now):
            self.assert_alarm_cleanup(use)
        self.assertEqual(len(directories), 1)
        self.assertFalse(directories[0].exists())

    def test_dns_child_does_not_inherit_worker_credentials(self):
        original = subprocess.Popen
        seen = []

        def spawn(*args, **kwargs):
            seen.append(kwargs["env"])
            return original(*args, **kwargs)

        # The real child asserts absence itself before performing numeric DNS.
        script = "import os;assert not any(x in os.environ for x in ('WORKER_TOKEN','DATABASE_URL','SOURCE_SECRET'));" + targets._DNS_SCRIPT
        with patch.dict(os.environ, {"WORKER_TOKEN": "synthetic", "DATABASE_URL": "synthetic", "SOURCE_SECRET": "synthetic"}), patch.object(targets, "_DNS_SCRIPT", script), patch.object(targets.subprocess, "Popen", side_effect=spawn):
            rows = targets._resolve("10.8.0.4", 5432, time.monotonic() + 3)
        self.assertEqual(rows, (ipaddress.ip_address("10.8.0.4"),))
        self.assertEqual(seen, [{"LANG": "C", "LC_ALL": "C"}])


if __name__ == "__main__":
    unittest.main()
