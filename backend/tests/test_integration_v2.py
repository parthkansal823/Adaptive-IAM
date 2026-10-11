"""Cross-module authority tests for session-linked apps and private enrollment."""
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.oauth import pkce
from backend.app.security import totp
from backend.app.store import PASSWORD, hash_password, now, stamp


class IdentityIntegrationTests(unittest.TestCase):
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
            for table in ('sessions','challenges','totp_factors','recovery_codes','passkeys','passkey_challenges','identity_limits','auth_failures'):
                db.execute('DELETE FROM '+table)
            db.execute("UPDATE users SET password_hash=? WHERE id='aisha'", (hash_password(PASSWORD),))
        self.tokens = {}
        for uid in ('aisha','kavya'):
            response = self.client.post('/api/auth/login',json={'user_id':uid,'password':PASSWORD,'context':{}})
            self.assertEqual(response.status_code,200,response.text)
            self.tokens[uid] = response.json()['token']

    def headers(self, uid='aisha'):
        return {'Authorization':'Bearer '+self.tokens[uid]}

    def fresh(self, uid='aisha'):
        sid = self.application.state.store.session(self.tokens[uid])['session']['id']
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE session_security SET verified_at=?,verification_method='totp' WHERE session_id=?", (stamp(),sid))

    def website_token(self, organization_id=None, resource_ids=None):
        actor = 'aisha' if organization_id else 'kavya'
        result = self.client.post('/api/apps',headers=self.headers(actor),json={'name':'Integration boundary','redirect_uris':['http://localhost:3001/callback'],'organization_id':organization_id,'resource_ids':resource_ids or []})
        self.assertEqual(result.status_code,201,result.text)
        app = result.json()
        query = dict(client_id=app['client_id'],response_type='code',redirect_uri=app['redirect_uris'][0],scope='openid iam:permissions',state='integration-state-123',nonce='integration-nonce-123',code_challenge=pkce('I'*64),code_challenge_method='S256')
        authorization = self.client.get('/oauth/authorize?'+urlencode(query),follow_redirects=False)
        self.assertEqual(authorization.status_code,302)
        rid = parse_qs(urlsplit(authorization.headers['location']).query)['request_id'][0]
        consent = self.client.post('/api/oauth/consent',headers=self.headers(),json={'request_id':rid,'approve':True})
        self.assertEqual(consent.status_code,200,consent.text)
        code = parse_qs(urlsplit(consent.json()['redirect_to']).query)['code'][0]
        issued = self.client.post('/oauth/token',data=dict(grant_type='authorization_code',client_id=app['client_id'],redirect_uri=app['redirect_uris'][0],code=code,code_verifier='I'*64))
        self.assertEqual(issued.status_code,200,issued.text)
        return issued.json()['access_token']

    def test_rp_headers_do_not_rebind_source_browser(self):
        token = self.website_token()
        response = self.client.get('/oauth/userinfo',headers={'Authorization':'Bearer '+token,'User-Agent':'Independent relying-party HTTP server','X-Forwarded-For':'198.51.100.9'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['sub'],'aisha')

    def test_source_expiry_denies_unexpired_app_token(self):
        token = self.website_token()
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE sessions SET expires_at=? WHERE user_id='aisha'", (stamp(now()-timedelta(seconds=1)),))
        self.assertEqual(self.client.get('/oauth/userinfo',headers={'Authorization':'Bearer '+token}).status_code,401)

    def test_direct_rp_check_observes_password_failures_without_console_guard(self):
        token = self.website_token()
        for _ in range(3):
            failed = self.client.post('/api/auth/login',json={'user_id':'aisha','password':'Incorrect password','context':{}})
            self.assertEqual(failed.status_code,401)
        # No /auth/me or authenticated console request is made after the failures.
        self.assertEqual(self.client.get('/oauth/userinfo',headers={'Authorization':'Bearer '+token}).status_code,401)

    def test_owner_removal_invalidates_existing_app_resource_mapping(self):
        self.fresh()
        organization = self.client.post('/api/developer/organizations',headers=self.headers(),json={'name':'Owned resource study'})
        self.assertEqual(organization.status_code,201)
        oid = organization.json()['id']
        self.assertEqual(self.client.post(f'/api/developer/organizations/{oid}/members',headers=self.headers(),json={'user_id':'meera','role':'member'}).status_code,200)
        token = self.website_token(oid,['research-vault'])
        rp_headers = {'Authorization':'Bearer '+token}
        self.assertEqual(self.client.get('/oauth/permissions/research-vault',headers=rp_headers).status_code,200)
        self.assertEqual(self.client.delete(f'/api/developer/organizations/{oid}/members/meera',headers=self.headers()).status_code,200)
        # The subject remains a member, but the resource owner no longer does.
        self.assertEqual(self.client.get('/oauth/userinfo',headers=rp_headers).status_code,200)
        self.assertEqual(self.client.get('/oauth/permissions/research-vault',headers=rp_headers).status_code,403)

    def private_bootstrap(self):
        password = 'Private integration passphrase 2026'
        with self.application.state.store.connection(write=True) as db:
            db.execute("DELETE FROM sessions WHERE user_id='aisha'")
            db.execute("UPDATE users SET password_hash=? WHERE id='aisha'", (hash_password(password),))
        self.application.state.identity.context.demo_mode = False
        response = self.client.post('/api/auth/login',json={'user_id':'aisha','password':password,'context':{'known_device':True,'prior_risk':0}})
        self.assertEqual(response.status_code,200,response.text)
        result = response.json()
        self.assertEqual(result['status'],'authenticated')
        self.assertTrue(result['enrollment_required'])
        self.assertEqual(result['session_scope'],'factor_enrollment')
        self.tokens['aisha'] = result['token']
        return password,result

    def test_private_bootstrap_is_short_and_has_no_protected_authority(self):
        password,result = self.private_bootstrap()
        sid = result['session_id']
        self.assertFalse(self.application.state.identity.check_session(sid))
        self.assertGreater(result['expires_at'],stamp())
        self.assertLess(result['expires_at'],stamp(now()+timedelta(minutes=6)))
        for path in ('/api/overview','/api/requests','/api/resources/research-vault/access','/api/developer/workspace'):
            response = self.client.get(path,headers=self.headers())
            self.assertEqual(response.status_code,403,response.text)
            self.assertEqual(response.json()['detail']['code'],'factor_enrollment_required')
        self.assertTrue(self.client.get('/api/auth/me',headers=self.headers()).json()['session']['enrollment_required'])
        self.assertEqual(self.client.post('/api/auth/reauth',headers=self.headers(),json={'password':password}).status_code,200)
        self.assertFalse(self.application.state.identity.check_session(sid))

    def test_confirmed_first_factor_upgrades_private_bootstrap(self):
        password,result = self.private_bootstrap()
        self.assertEqual(self.client.post('/api/auth/reauth',headers=self.headers(),json={'password':password}).status_code,200)
        packet = self.client.post('/api/auth/totp/enroll',headers=self.headers()).json()
        response = self.client.post('/api/auth/totp/confirm',headers=self.headers(),json={'enrollment_id':packet['enrollment_id'],'code':totp(packet['secret'],int(time.time())//30)})
        self.assertEqual(response.status_code,200,response.text)
        me = self.client.get('/api/auth/me',headers=self.headers()).json()
        self.assertFalse(me['session']['enrollment_required'])
        self.assertTrue(self.application.state.identity.check_session(result['session_id']))
        self.assertGreater(me['session']['expires_at'],stamp(now()+timedelta(minutes=29)))
        self.assertEqual(self.client.get('/api/overview',headers=self.headers()).status_code,200)

    def test_removing_last_private_factor_removes_protected_authority(self):
        password,result = self.private_bootstrap()
        self.client.post('/api/auth/reauth',headers=self.headers(),json={'password':password})
        packet = self.client.post('/api/auth/totp/enroll',headers=self.headers()).json()
        confirmed = self.client.post('/api/auth/totp/confirm',headers=self.headers(),json={'enrollment_id':packet['enrollment_id'],'code':totp(packet['secret'],int(time.time())//30)})
        self.assertEqual(confirmed.status_code,200)
        self.assertTrue(self.application.state.identity.check_session(result['session_id']))
        removed = self.client.delete('/api/auth/totp',headers=self.headers())
        self.assertEqual(removed.status_code,200)
        self.assertFalse(self.application.state.identity.check_session(result['session_id']))
        protected = self.client.get('/api/overview',headers=self.headers())
        self.assertEqual(protected.status_code,403)
        self.assertEqual(protected.json()['detail']['code'],'factor_enrollment_required')
        self.assertEqual(self.client.post('/api/auth/reauth',headers=self.headers(),json={'password':password}).status_code,200)
        self.assertEqual(self.client.get('/api/auth/security',headers=self.headers()).status_code,200)
        self.assertEqual(self.client.get('/api/overview',headers=self.headers()).status_code,403)


if __name__ == '__main__':
    unittest.main()
