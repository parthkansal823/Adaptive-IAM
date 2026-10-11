"""Real factor, session-boundary and WebAuthn cryptographic HTTP tests."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from backend.app.identity import b64
from backend.app.main import create_app
from backend.app.security import totp
from backend.app.store import PASSWORD, hash_password, now, stamp

try:
    import cbor2
    import webauthn
    CRYPTO_AVAILABLE = True
except (ImportError, OSError):
    CRYPTO_AVAILABLE = False


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.application = create_app(Path(cls.temp.name), Path(cls.temp.name)/'risk.joblib')
        cls.client = TestClient(cls.application)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        cls.temp.cleanup()

    def setUp(self):
        self.application.state.login_rate_state.clear()
        self.application.state.identity.context.demo_mode = True
        with self.application.state.store.connection(write=True) as db:
            for table in ('sessions', 'challenges', 'totp_factors', 'recovery_codes', 'passkeys', 'passkey_challenges', 'identity_limits', 'auth_failures'):
                db.execute('DELETE FROM '+table)
            db.execute("UPDATE users SET password_hash=? WHERE id='aisha'", (hash_password(PASSWORD),))
        self.token = self.login().json()['token']

    def login(self, **kwargs):
        return self.client.post('/api/auth/login', json={'user_id': 'aisha', 'password': PASSWORD, 'context': {}, **kwargs})

    def headers(self, token=None, agent=None):
        headers = {'Authorization': 'Bearer '+(token or self.token)}
        if agent:
            headers['User-Agent'] = agent
        return headers

    def reauth(self):
        response = self.client.post('/api/auth/reauth', headers=self.headers(), json={'password': PASSWORD})
        self.assertEqual(response.status_code, 200, response.text)

    def enroll(self):
        self.reauth()
        packet = self.client.post('/api/auth/totp/enroll', headers=self.headers()).json()
        self.counter = int(time.time())//30
        self.secret = packet['secret']
        response = self.client.post('/api/auth/totp/confirm', headers=self.headers(), json={'enrollment_id': packet['enrollment_id'], 'code': totp(self.secret, self.counter)})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['recovery_codes']

    def test_rfc6238_vector_and_enrollment_requires_fresh_password(self):
        self.assertEqual(totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1), '287082')
        response = self.client.post('/api/auth/totp/enroll', headers=self.headers())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['detail']['code'], 'recent_verification_required')

    def test_real_totp_login_replay_and_no_demo_bypass(self):
        self.enroll()
        packet = self.login().json()
        self.assertEqual(packet['status'], 'mfa_required')
        self.assertNotIn('demo_code', packet)
        self.assertIn('totp', packet['methods'])
        used = self.client.post('/api/auth/verify', json={'challenge_id': packet['challenge_id'], 'code': totp(self.secret, self.counter)})
        self.assertEqual(used.status_code, 401)
        future = self.counter+1
        with patch('backend.app.security.time.time', return_value=future*30):
            body = {'challenge_id': packet['challenge_id'], 'code': totp(self.secret, future)}
            response = self.client.post('/api/auth/verify', json=body)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['verification_method'], 'totp')
            self.assertEqual(self.client.post('/api/auth/verify', json=body).status_code, 401)

    def test_recovery_single_use_hash_only_and_secret_free_audit(self):
        codes = self.enroll()
        packet = self.login().json()
        response = self.client.post('/api/auth/verify', json={'challenge_id': packet['challenge_id'], 'recovery_code': codes[0]})
        self.assertEqual(response.status_code, 200, response.text)
        next_packet = self.login().json()
        self.assertEqual(self.client.post('/api/auth/verify', json={'challenge_id': next_packet['challenge_id'], 'recovery_code': codes[0]}).status_code, 401)
        with self.application.state.store.connection() as db:
            factor = db.execute('SELECT encrypted_secret FROM totp_factors').fetchone()[0]
            audit = ' '.join(row[0] for row in db.execute('SELECT payload FROM audit'))
            recovery = ' '.join(row[0] for row in db.execute('SELECT code_hash FROM recovery_codes'))
        self.assertNotIn(self.secret, factor)
        self.assertNotIn(self.secret, audit)
        self.assertNotIn(codes[0], audit+recovery)
        self.assertEqual(response.headers['cache-control'], 'no-store')

    def test_changed_context_denies_resource_vote_and_password_rebind(self):
        other_session = self.login().json()['session_id']
        headers = self.headers(agent='different browser')
        for path in ('/api/resources/research-vault/access', '/api/requests', '/api/apps'):
            response = self.client.get(path, headers=headers)
            self.assertEqual(response.status_code, 403, response.text)
            self.assertEqual(response.json()['detail']['code'], 'step_up_required')
        denied = self.client.post('/api/requests/missing/votes', headers=headers, json={'approve': True})
        self.assertEqual(denied.status_code, 403)
        denied = self.client.post('/api/auth/reauth', headers=headers, json={'password': PASSWORD})
        self.assertEqual(denied.status_code, 401)
        denied = self.client.post('/api/auth/sessions/'+other_session+'/revoke', headers=headers)
        self.assertEqual(denied.status_code, 403)
        me = self.client.get('/api/auth/me', headers=headers)
        self.assertTrue(me.json()['session']['step_up_required'])

    def test_factor_clears_changed_context_and_five_failures_revoke(self):
        codes = self.enroll()
        headers = self.headers(agent='changed browser')
        self.assertEqual(self.client.get('/api/overview', headers=headers).status_code, 403)
        verified = self.client.post('/api/auth/step-up', headers=headers, json={'recovery_code': codes[0]})
        self.assertEqual(verified.status_code, 200)
        self.assertEqual(self.client.get('/api/overview', headers=headers).status_code, 200)
        for _ in range(5):
            self.assertEqual(self.client.post('/api/auth/step-up', headers=headers, json={'recovery_code': 'invalid-recovery'}).status_code, 401)
        self.assertEqual(self.client.get('/api/auth/me', headers=headers).status_code, 401)

    def test_session_revocation_and_source_check(self):
        second = self.login().json()
        listing = self.client.get('/api/auth/sessions', headers=self.headers()).json()['items']
        self.assertEqual(len(listing), 2)
        sid = second['session_id']
        self.assertTrue(self.application.state.identity.check_session(sid))
        result = self.client.post('/api/auth/sessions/'+sid+'/revoke', headers=self.headers())
        self.assertEqual(result.status_code, 200)
        self.assertFalse(self.application.state.identity.check_session(sid))
        self.assertEqual(self.client.get('/api/auth/me', headers=self.headers(second['token'])).status_code, 401)

    def test_untrusted_forwarding_cannot_change_context(self):
        headers = {**self.headers(), 'X-Forwarded-For': '198.51.100.9'}
        self.assertEqual(self.client.get('/api/overview', headers=headers).status_code, 200)

    def test_server_password_failure_spike_gates_live_session(self):
        codes = self.enroll()
        for _ in range(3):
            self.assertEqual(self.login(password='wrong password').status_code, 401)
        response = self.client.get('/api/resources/research-vault/access', headers=self.headers())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['detail']['code'], 'step_up_required')
        verified = self.client.post('/api/auth/step-up', headers=self.headers(), json={'recovery_code': codes[0]})
        self.assertEqual(verified.status_code, 200)
        self.assertEqual(self.client.get('/api/overview', headers=self.headers()).status_code, 200)

    def test_secure_mode_rejects_public_seed_and_old_demo_sessions(self):
        self.application.state.identity.context.demo_mode = False
        bootstrap = self.client.get('/api/bootstrap').json()
        self.assertFalse(bootstrap['demo_mode'])
        self.assertEqual(bootstrap['users'], [])
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(self.client.get('/api/auth/me', headers=self.headers()).status_code, 401)
        self.assertFalse(self.application.state.identity.check_session(self.application.state.store.session(self.token)['session']['id']))
        private_password = 'An operator chosen private passphrase!'
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE users SET password_hash=? WHERE id='aisha'", (hash_password(private_password),))
        response = self.login(password=private_password, context={'known_device': True, 'vpn': False, 'failed_attempts': 0}).json()
        self.assertIn('server_request_observed', response['risk']['context_source'])
        self.assertIn('vpn_detection', response['risk']['unavailable_features'])

    def test_demo_challenge_is_bound_and_exactly_one_factor(self):
        medium = {'known_device': False, 'known_location': False, 'failed_attempts': 1, 'login_velocity': 2, 'travel_distance_km': 6500}
        packet = self.login(context=medium).json()
        body = {'challenge_id': packet['challenge_id'], 'code': packet['demo_code']}
        self.assertEqual(self.client.post('/api/auth/verify', headers={'User-Agent': 'wrong'}, json=body).status_code, 401)
        self.assertEqual(self.client.post('/api/auth/verify', json={**body, 'recovery_code': 'another-factor'}).status_code, 422)

    def test_operator_provisioning_hashes_password_and_resets_sessions(self):
        from scripts.provision_identity import provision
        password = 'Private operator provision passphrase!'
        with self.assertRaises(ValueError):
            provision(self.application.state.store.path, 'aisha', 'Aisha', 'analyst', 'Engineering', PASSWORD)
        provision(self.application.state.store.path, 'aisha', 'Aisha', 'analyst', 'Engineering', password)
        self.assertEqual(self.client.get('/api/auth/me', headers=self.headers()).status_code, 401)
        self.application.state.identity.context.demo_mode = False
        result = self.login(password=password)
        self.assertEqual(result.status_code, 200, result.text)
        with self.application.state.store.connection() as db:
            encoded = db.execute("SELECT password_hash FROM users WHERE id='aisha'").fetchone()[0]
        self.assertNotIn(password, encoded)


@unittest.skipUnless(CRYPTO_AVAILABLE, 'WebAuthn native dependency unavailable; execute crypto suite in Docker Linux')
class PasskeyCryptoTests(unittest.TestCase):
    """Generate actual P-256 signatures/COSE keys, not mocked verification."""
    setUpClass = classmethod(IdentityTests.setUpClass.__func__)
    tearDownClass = classmethod(IdentityTests.tearDownClass.__func__)
    setUp = IdentityTests.setUp
    login = IdentityTests.login
    headers = IdentityTests.headers
    reauth = IdentityTests.reauth
    def registration(self, challenge, origin=None, flags=0x45):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.private = ec.generate_private_key(ec.SECP256R1())
        public = self.private.public_key().public_numbers()
        self.credential_id = secrets.token_bytes(24)
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, 'big'), -3: public.y.to_bytes(32, 'big')})
        auth_data = hashlib.sha256(b'127.0.0.1').digest()+bytes([flags])+struct.pack('>I', 1)+bytes(16)+struct.pack('>H', len(self.credential_id))+self.credential_id+cose
        client_data = json.dumps({'type': 'webauthn.create', 'challenge': challenge, 'origin': origin or 'http://127.0.0.1:5173'}).encode()
        return {'id': b64(self.credential_id), 'rawId': b64(self.credential_id), 'type': 'public-key', 'response': {'clientDataJSON': b64(client_data), 'attestationObject': b64(cbor2.dumps({'fmt': 'none', 'authData': auth_data, 'attStmt': {}}))}}

    def assertion(self, challenge, *, counter=2, origin=None, flags=5, wrong_key=False, rp_id='127.0.0.1', user_handle=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        client_data = json.dumps({'type': 'webauthn.get', 'challenge': challenge, 'origin': origin or 'http://127.0.0.1:5173'}).encode()
        auth_data = hashlib.sha256(rp_id.encode()).digest()+bytes([flags])+struct.pack('>I', counter)
        key = ec.generate_private_key(ec.SECP256R1()) if wrong_key else self.private
        response = {'clientDataJSON': b64(client_data), 'authenticatorData': b64(auth_data), 'signature': b64(key.sign(auth_data+hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())))}
        if user_handle is not None:
            response['userHandle'] = user_handle
        return {'id': b64(self.credential_id), 'rawId': b64(self.credential_id), 'type': 'public-key', 'response': response}

    def register(self):
        self.reauth()
        packet = self.client.post('/api/auth/passkeys/register/options', headers=self.headers(), json={'label': 'Cryptographic test key'}).json()
        credential = self.registration(packet['options']['challenge'])
        result = self.client.post('/api/auth/passkeys/register/verify', headers=self.headers(), json={'challenge_id': packet['challenge_id'], 'credential': credential})
        self.assertEqual(result.status_code, 200, result.text)
        return packet, credential

    def options(self):
        result = self.client.post('/api/auth/passkeys/login/options', json={'user_id': 'aisha'})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def test_crypto_registration_login_and_replay(self):
        packet, credential = self.register()
        replay = self.client.post('/api/auth/passkeys/register/verify', headers=self.headers(), json={'challenge_id': packet['challenge_id'], 'credential': credential})
        self.assertEqual(replay.status_code, 401)
        packet = self.options()
        body = {'challenge_id': packet['challenge_id'], 'credential': self.assertion(packet['options']['challenge'])}
        result = self.client.post('/api/auth/passkeys/login/verify', json=body)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['verification_method'], 'passkey')
        self.assertEqual(self.client.post('/api/auth/passkeys/login/verify', json=body).status_code, 401)

    def test_crypto_wrong_origin_signature_uv_rp_handle_and_counter_denied(self):
        self.register()
        for changes in ({'origin': 'https://attacker.example'}, {'wrong_key': True}, {'flags': 1}, {'rp_id': 'attacker.example'}, {'user_handle': b64(b'wrong-user')}, {'counter': 1}):
            with self.subTest(changes=changes):
                packet = self.options()
                body = {'challenge_id': packet['challenge_id'], 'credential': self.assertion(packet['options']['challenge'], **changes)}
                self.assertEqual(self.client.post('/api/auth/passkeys/login/verify', json=body).status_code, 401)

    def test_crypto_registration_origin_and_uv_required(self):
        self.reauth()
        for changes in ({'origin': 'https://attacker.example'}, {'flags': 0x41}):
            packet = self.client.post('/api/auth/passkeys/register/options', headers=self.headers(), json={'label': 'Rejected key'}).json()
            credential = self.registration(packet['options']['challenge'], **changes)
            result = self.client.post('/api/auth/passkeys/register/verify', headers=self.headers(), json={'challenge_id': packet['challenge_id'], 'credential': credential})
            self.assertEqual(result.status_code, 401)

    def test_crypto_step_up_rebinds_only_after_valid_assertion(self):
        self.register()
        headers = self.headers(agent='different legitimate browser')
        self.assertEqual(self.client.get('/api/overview', headers=headers).status_code, 403)
        packet = self.client.post('/api/auth/passkeys/step-up/options', headers=headers).json()
        body = {'challenge_id': packet['challenge_id'], 'credential': self.assertion(packet['options']['challenge'])}
        result = self.client.post('/api/auth/passkeys/step-up/verify', headers=headers, json=body)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.client.get('/api/overview', headers=headers).status_code, 200)
