#!/usr/bin/env python3
import unittest
import tempfile
import os
import sqlite3
from port_reporter import RegionErrorWatch, all_tasks_idle, parse_source


class ReporterTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(parse_source("n192.0.2.10:50000->198.51.100.5:443"),
                         ("192.0.2.10", 50000))

    def test_ipv6_canonicalization(self):
        self.assertEqual(parse_source("n[2001:0db8::1]:50000->[2001:db8::2]:443"),
                         ("2001:db8::1", 50000))

    def test_loopback_is_omitted(self):
        self.assertIsNone(parse_source("n127.0.0.1:50000->127.0.0.1:50001"))

    def test_invalid_and_link_local_are_omitted(self):
        self.assertIsNone(parse_source("n[fe80::1%en0]:5->[fe80::2]:5"))
        self.assertIsNone(parse_source("n192.0.2.10:99999->198.51.100.5:443"))
        self.assertIsNone(parse_source("ninvalid"))

    def test_only_new_explicit_location_error_is_reported_temporarily(self):
        with tempfile.NamedTemporaryFile() as log:
            log.write(b"PERMISSION_DENIED Detected location: CN\n")
            log.flush()
            now = [0]
            watcher = RegionErrorWatch(log.name, lambda: now[0])
            self.assertFalse(watcher.recent())  # Existing log is not replayed.
            log.write(b"ordinary text Detected location: CN\n")
            log.flush()
            self.assertFalse(watcher.recent())
            log.write(b"PERMISSION_DENIED Detected location: CN\n")
            log.flush()
            self.assertTrue(watcher.recent())
            now[0] = 91
            self.assertFalse(watcher.recent())

    def test_task_state_gate_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'summary.db')
            self.assertFalse(all_tasks_idle(path))
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE conversation_summaries(status text, not_fully_idle integer)')
                self.assertFalse(all_tasks_idle(path))  # No known conversations.
                db.execute('INSERT INTO conversation_summaries VALUES (?,?)',
                           ('CASCADE_RUN_STATUS_IDLE', 0))
            self.assertTrue(all_tasks_idle(path))
            with sqlite3.connect(path) as db:
                db.execute('INSERT INTO conversation_summaries VALUES (?,?)',
                           ('CASCADE_RUN_STATUS_RUNNING', 1))
            self.assertFalse(all_tasks_idle(path))
            with sqlite3.connect(path) as db:
                db.execute('UPDATE conversation_summaries SET status=?, not_fully_idle=1',
                           ('CASCADE_RUN_STATUS_IDLE',))
            self.assertFalse(all_tasks_idle(path))
            with sqlite3.connect(path) as db:
                db.execute('UPDATE conversation_summaries SET status=?, not_fully_idle=0',
                           ('UNKNOWN',))
            self.assertFalse(all_tasks_idle(path))


if __name__ == "__main__":
    unittest.main()
