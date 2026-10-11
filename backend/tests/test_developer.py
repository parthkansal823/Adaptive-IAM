"""HTTP authority boundaries for onboarding, session-linked OAuth and diagnostics."""
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.oauth import pkce
from backend.app.store import PASSWORD, stamp


class DeveloperBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.application = create_app(Path(cls.temp.name), Path(cls.temp.name)/'risk.joblib')
        cls.client = TestClient(cls.application)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None,None,None)
        cls.temp.cleanup()

    def setUp(self):
        self.application.state.login_rate_state.clear()
        self.tokens = {}
        for uid in ('aisha','kavya','meera','rohan'):
            result = self.client.post('/api/auth/login',json={'user_id':uid,'password':PASSWORD,'context':{}})
            self.assertEqual(result.status_code,200)
            self.tokens[uid] = result.json()['token']

    def headers(self, uid='aisha'):
        return {'Authorization':'Bearer '+self.tokens[uid]}

    def fresh(self, uid):
        # A trusted server fixture represents a completed factor verification.
        # No client endpoint can submit verification timestamps or methods.
        sid = self.application.state.store.session(self.tokens[uid])['session']['id']
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE session_security SET verified_at=?,verification_method='totp',step_up_required=0 WHERE session_id=?",(stamp(),sid))

    def organization(self):
        self.fresh('aisha')
        response = self.client.post('/api/developer/organizations',headers=self.headers(),json={'name':'Boundary study'})
        self.assertEqual(response.status_code,201)
        return response.json()['id']

    def app(self, organization_id=None, confidential=False):
        actor = 'aisha' if organization_id else 'kavya'
        response = self.client.post('/api/apps',headers=self.headers(actor),json={'name':'Boundary website','redirect_uris':['http://127.0.0.1:3001/callback'],'client_type':'confidential' if confidential else 'public','organization_id':organization_id})
        self.assertEqual(response.status_code,201)
        return response.json()

    def code(self, app, uid='aisha'):
        query = {'client_id':app['client_id'],'response_type':'code','redirect_uri':app['redirect_uris'][0],'scope':'openid profile','state':'boundary-state-123456','nonce':'boundary-nonce-123456','code_challenge':pkce('B'*64),'code_challenge_method':'S256'}
        response = self.client.get('/oauth/authorize?'+urlencode(query),follow_redirects=False)
        self.assertEqual(response.status_code,302)
        request_id = parse_qs(urlsplit(response.headers['location']).query)['request_id'][0]
        consent = self.client.post('/api/oauth/consent',headers=self.headers(uid),json={'request_id':request_id,'approve':True})
        return consent

    def exchange(self, app, consent, secret=None):
        code = parse_qs(urlsplit(consent.json()['redirect_to']).query)['code'][0]
        body={'grant_type':'authorization_code','code':code,'client_id':app['client_id'],'redirect_uri':app['redirect_uris'][0],'code_verifier':'B'*64}
        if secret:
            body['client_secret']=secret
        return self.client.post('/oauth/token',data=body)

    def test_new_organization_requires_recent_real_factor(self):
        result=self.client.post('/api/developer/organizations',headers=self.headers(),json={'name':'Unverified organization'})
        self.assertEqual(result.status_code,403)
        self.assertEqual(result.json()['detail']['code'],'recent_verification_required')

    def test_nonmember_cannot_manage_or_consent_to_org_app(self):
        org=self.organization()
        app=self.app(org)
        self.fresh('kavya')
        result=self.client.post(f'/api/developer/organizations/{org}/members',headers=self.headers('kavya'),json={'user_id':'rohan','role':'admin'})
        self.assertEqual(result.status_code,403)
        self.assertEqual(self.code(app,'kavya').status_code,403)
        self.assertEqual(self.client.delete('/api/apps/'+app['client_id'],headers=self.headers('kavya')).status_code,403)

    def test_last_admin_cannot_be_removed_or_demoted(self):
        org=self.organization()
        self.assertEqual(self.client.delete(f'/api/developer/organizations/{org}/members/aisha',headers=self.headers()).status_code,409)
        self.assertEqual(self.client.post(f'/api/developer/organizations/{org}/members',headers=self.headers(),json={'user_id':'aisha','role':'member'}).status_code,409)

    def test_member_role_cannot_register_app_or_change_members(self):
        org=self.organization()
        self.client.post(f'/api/developer/organizations/{org}/members',headers=self.headers(),json={'user_id':'rohan','role':'member'})
        self.fresh('rohan')
        body={'name':'Not allowed','redirect_uris':['http://localhost:3001/callback'],'organization_id':org}
        self.assertEqual(self.client.post('/api/apps',headers=self.headers('rohan'),json=body).status_code,403)
        self.assertEqual(self.client.post(f'/api/developer/organizations/{org}/members',headers=self.headers('rohan'),json={'user_id':'meera','role':'admin'}).status_code,403)

    def test_owner_membership_required_for_resource_mapping(self):
        org=self.organization()
        body={'name':'Scoped website','redirect_uris':['http://localhost:3001/callback'],'organization_id':org,'resource_ids':['research-vault']}
        self.assertEqual(self.client.post('/api/apps',headers=self.headers(),json=body).status_code,422)
        self.client.post(f'/api/developer/organizations/{org}/members',headers=self.headers(),json={'user_id':'meera','role':'member'})
        self.assertEqual(self.client.post('/api/apps',headers=self.headers(),json=body).status_code,201)

    def test_source_session_revocation_denies_app_token(self):
        app=self.app()
        issued=self.exchange(app,self.code(app))
        self.assertEqual(issued.status_code,200)
        authorization={'Authorization':'Bearer '+issued.json()['access_token']}
        self.assertEqual(self.client.get('/oauth/userinfo',headers=authorization).status_code,200)
        sid=self.application.state.store.session(self.tokens['aisha'])['session']['id']
        with self.application.state.store.connection(write=True) as db:
            db.execute('DELETE FROM sessions WHERE id=?',(sid,))
        self.assertEqual(self.client.get('/oauth/userinfo',headers=authorization).status_code,401)

    def test_source_session_stepup_denies_code_exchange(self):
        app=self.app()
        consent=self.code(app)
        sid=self.application.state.store.session(self.tokens['aisha'])['session']['id']
        with self.application.state.store.connection(write=True) as db:
            db.execute('UPDATE session_security SET step_up_required=1 WHERE session_id=?',(sid,))
        self.assertEqual(self.exchange(app,consent).status_code,400)

    def test_membership_removal_immediately_revokes_app_access(self):
        org=self.organization()
        self.client.post(f'/api/developer/organizations/{org}/members',headers=self.headers(),json={'user_id':'rohan','role':'member'})
        app=self.app(org)
        issued=self.exchange(app,self.code(app,'rohan'))
        self.assertEqual(issued.status_code,200)
        authorization={'Authorization':'Bearer '+issued.json()['access_token']}
        self.assertEqual(self.client.get('/oauth/userinfo',headers=authorization).status_code,200)
        self.client.delete(f'/api/developer/organizations/{org}/members/rohan',headers=self.headers())
        self.assertEqual(self.client.get('/oauth/userinfo',headers=authorization).status_code,401)

    def test_rotation_requires_factor_and_revokes_existing_tokens(self):
        app=self.app(confidential=True)
        issued=self.exchange(app,self.code(app),app['client_secret'])
        self.assertEqual(issued.status_code,200)
        path='/api/apps/'+app['client_id']+'/rotate-secret'
        self.assertEqual(self.client.post(path,headers=self.headers('kavya'),json={}).status_code,403)
        self.fresh('kavya')
        rotated=self.client.post(path,headers=self.headers('kavya'),json={})
        self.assertEqual(rotated.status_code,200)
        self.assertEqual(rotated.headers['cache-control'],'no-store')
        self.assertNotEqual(rotated.json()['client_secret'],app['client_secret'])
        self.assertEqual(self.client.get('/oauth/userinfo',headers={'Authorization':'Bearer '+issued.json()['access_token']}).status_code,401)
        with self.application.state.store.connection() as db:
            serialized=json.dumps(self.application.state.store.audit_dtos(db))
        self.assertNotIn(rotated.json()['client_secret'],serialized)

    def test_callback_check_does_not_fetch_arbitrary_urls(self):
        result=self.client.post('/api/developer/callback-check',headers=self.headers(),json={'redirect_uri':'http://169.254.169.254/latest/meta-data/'})
        self.assertEqual(result.status_code,200)
        self.assertFalse(result.json()['valid'])
        self.assertFalse(result.json()['network_request_performed'])

    def test_attack_lab_writes_no_authorization_and_is_actor_scoped(self):
        with self.application.state.store.connection() as db:
            before=[db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ('requests','votes','grants')]
        response=self.client.post('/api/lab/run',headers=self.headers(),json={'case_id':'fake-votes'})
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()['grant_created'])
        self.assertTrue(response.json()['human_approval_required'])
        run_id=response.json()['id']
        with self.application.state.store.connection() as db:
            after=[db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ('requests','votes','grants')]
        self.assertEqual(before,after)
        self.assertNotIn(run_id,[r['id'] for r in self.client.get('/api/lab/runs',headers=self.headers('rohan')).json()['items']])
        self.assertEqual(self.client.post('/api/lab/run',headers=self.headers(),json={'case_id':'fake-votes','user_id':'kavya'}).status_code,422)


if __name__=='__main__':
    unittest.main()
