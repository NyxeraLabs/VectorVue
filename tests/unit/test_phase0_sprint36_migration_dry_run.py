# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0
#
# You may:
# Study
# Modify
# Use for internal security testing
#
# You may NOT:
# Offer as a commercial service
# Sell derived competing products

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from vv_core import Database, SessionCrypto


class MigrationDryRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_db_name = Database.DB_NAME
        self._orig_session_file = os.environ.get("VV_SESSION_FILE")
        self._tmpdir = tempfile.TemporaryDirectory(prefix="vv_sprint36_migrate_")
        self._db_path = Path(self._tmpdir.name) / "vectorvue_sprint36.db"
        Database.DB_NAME = str(self._db_path)
        os.environ["VV_SESSION_FILE"] = str(Path(self._tmpdir.name) / ".session")

    def tearDown(self) -> None:
        Database.DB_NAME = self._orig_db_name
        if self._orig_session_file is None:
            os.environ.pop("VV_SESSION_FILE", None)
        else:
            os.environ["VV_SESSION_FILE"] = self._orig_session_file
        self._tmpdir.cleanup()

    @staticmethod
    def _bootstrap_db() -> Database:
        crypto = SessionCrypto()
        crypto.derive_key("Sprint36MigrationDryRunPassphrase!")
        return Database(crypto)

    @staticmethod
    def _schema_snapshot(db_path: Path) -> dict[str, tuple[str, ...]]:
        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            tables = [row[0] for row in cur.fetchall()]
            snapshot: dict[str, tuple[str, ...]] = {}
            for table in tables:
                cur.execute(f"PRAGMA table_info('{table}')")
                cols = tuple(row[1] for row in cur.fetchall())
                snapshot[table] = cols
            return snapshot
        finally:
            conn.close()

    def test_sqlite_migrations_are_idempotent_for_dry_run(self) -> None:
        first = self._bootstrap_db()
        first.close()

        snapshot_before = self._schema_snapshot(self._db_path)
        self.assertIn("campaigns", snapshot_before)
        self.assertIn("detection_events", snapshot_before)
        self.assertIn("technique_patterns", snapshot_before)

        second = self._bootstrap_db()
        second.close()

        snapshot_after = self._schema_snapshot(self._db_path)
        self.assertEqual(snapshot_before, snapshot_after)


if __name__ == "__main__":
    unittest.main()
