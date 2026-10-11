"""Offline, interactive identity provisioning. Stop the API before running."""
from __future__ import annotations

import argparse
import getpass
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.store import PASSWORD, Store, hash_password

ROLES = ('analyst', 'resource_owner', 'security_reviewer', 'department_reviewer')


def provision(database, user_id, name, role, department, password):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', user_id):
        raise ValueError('Identity ID must contain 1–80 letters, numbers, underscores or hyphens')
    if role not in ROLES or not 1 <= len(name) <= 100 or not 1 <= len(department) <= 80:
        raise ValueError('Invalid identity metadata')
    if len(password) < 14 or len(password) > 256 or password == PASSWORD:
        raise ValueError('Use a private passphrase of 14–256 characters; public demo passwords are forbidden')
    store = Store(Path(database))
    with store.connection(write=True) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        db.execute('INSERT INTO users VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,role=excluded.role,department=excluded.department,password_hash=excluded.password_hash', (user_id, name, role, department, hash_password(password)))
        for table in ('sessions', 'challenges', 'totp_factors', 'recovery_codes', 'passkeys', 'passkey_challenges', 'factor_enrollments', 'auth_failures'):
            if table in tables:
                db.execute('DELETE FROM '+table+' WHERE user_id=?', (user_id,))
        store.audit(db, 'identity_operator_provisioned', user_id, {'role': role, 'sessions_revoked': True, 'factors_reset': True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, help='Explicit SQLite path under this workspace, or /var/lib/iam inside Docker')
    parser.add_argument('--user-id', required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--department', required=True)
    parser.add_argument('--role', choices=ROLES, default='analyst')
    args = parser.parse_args()
    database = Path(args.database).resolve()
    allowed = database.is_relative_to(ROOT) or (Path('/.dockerenv').exists() and database.is_relative_to(Path('/var/lib/iam')))
    if not allowed or database.suffix not in ('.sqlite3', '.sqlite', '.db'):
        parser.error('Database must resolve inside the workspace or Docker IAM volume and use a SQLite extension')
    password = getpass.getpass('Private passphrase (not a demo password): ')
    if password != getpass.getpass('Repeat private passphrase: '):
        parser.error('Passphrases do not match')
    try:
        provision(database, args.user_id, args.name, args.role, args.department, password)
    except ValueError as exc:
        parser.error(str(exc))
    print('Identity provisioned. Existing sessions and factors for this identity were revoked; enroll a fresh factor after signing in.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
