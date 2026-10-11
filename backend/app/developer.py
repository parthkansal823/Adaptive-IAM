"""Organization-scoped website onboarding; membership never creates resource grants."""
from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import Field

from .models import StrictInput
from .store import stamp


class OrganizationInput(StrictInput):
    name: str = Field(min_length=2, max_length=80)


class MemberInput(StrictInput):
    user_id: str = Field(min_length=1, max_length=80)
    role: str = Field("member", pattern="^(admin|developer|member)$")


class CallbackInput(StrictInput):
    redirect_uri: str = Field(min_length=1, max_length=2048)
    client_id: str | None = Field(None, min_length=1, max_length=128)


class DeveloperPortal:
    def __init__(self, store):
        self.store = store
        with store.connection(write=True) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS organization_members (organization_id TEXT NOT NULL REFERENCES organizations(id), user_id TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL CHECK(role IN ('admin','developer','member')), PRIMARY KEY(organization_id,user_id));
            """)
            if not db.execute("SELECT 1 FROM organizations WHERE id='research-demo'").fetchone():
                db.execute("INSERT INTO organizations VALUES ('research-demo','Research workspace','kavya',?)", (stamp(),))
                for user in db.execute("SELECT id FROM users").fetchall():
                    db.execute("INSERT INTO organization_members VALUES ('research-demo',?,?)", (user['id'], 'admin' if user['id'] == 'kavya' else 'member'))

    @staticmethod
    def role(db, organization_id, user_id):
        row = db.execute("SELECT role FROM organization_members WHERE organization_id=? AND user_id=?", (organization_id, user_id)).fetchone()
        return row['role'] if row else None

    def require_member(self, db, organization_id, user_id, roles=None):
        role = self.role(db, organization_id, user_id)
        if not role or (roles and role not in roles):
            raise HTTPException(403, "Organization membership does not permit this action")
        return role

    def can_manage(self, db, application, identity):
        organization_id = application['organization_id']
        return self.role(db, organization_id, identity['user']['id']) in {'admin', 'developer'} if organization_id else identity['user']['role'] == 'security_reviewer'

    def require_app_manager(self, db, application, identity):
        if not self.can_manage(db, application, identity):
            raise HTTPException(403, "Only this organization's administrators/developers may manage its app")

    def allow_subject(self, db, application, user_id):
        if application['organization_id']:
            self.require_member(db, application['organization_id'], user_id)

    @staticmethod
    def resource_ids(db, organization_id):
        # A resource can be mapped only while its owner belongs to the organization.
        # The resource is still shared prototype infrastructure; grants remain separate.
        return [r['id'] for r in db.execute("SELECT r.id FROM resources r JOIN organization_members m ON r.owner_id=m.user_id WHERE m.organization_id=? ORDER BY r.id", (organization_id,))]

    def organization_dto(self, db, organization_id, user_id):
        row = db.execute("SELECT * FROM organizations WHERE id=?", (organization_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Organization not found")
        role = self.require_member(db, organization_id, user_id)
        members = [dict(r) for r in db.execute("SELECT m.user_id,u.name,m.role FROM organization_members m JOIN users u ON m.user_id=u.id WHERE m.organization_id=? ORDER BY u.name", (organization_id,))]
        return {'id': row['id'], 'name': row['name'], 'role': role, 'can_manage': role in {'admin','developer'}, 'members': members, 'resource_ids': self.resource_ids(db, organization_id)}

    def app_dto(self, db, application, identity, provider):
        packet = provider.app_dto(application)
        organization = db.execute("SELECT name FROM organizations WHERE id=?", (application['organization_id'],)).fetchone()
        return {**packet, 'organization_id': application['organization_id'], 'organization_name': organization['name'] if organization else None, 'can_manage': self.can_manage(db, application, identity)}


def install_developer(api, authenticated):
    def recent(identity):
        api.state.identity.require_recent(identity, require_factor=True)

    @api.get('/api/developer/workspace')
    def workspace(identity=Depends(authenticated)):
        portal, provider = api.state.developer, api.state.oauth
        actor = identity['user']['id']
        with portal.store.connection() as db:
            memberships = db.execute('SELECT organization_id FROM organization_members WHERE user_id=? ORDER BY organization_id', (actor,)).fetchall()
            organizations = [portal.organization_dto(db, r['organization_id'], actor) for r in memberships]
            applications = db.execute('SELECT * FROM oauth_apps ORDER BY created_at DESC').fetchall()
            visible = [a for a in applications if identity['user']['role'] == 'security_reviewer' or portal.role(db, a['organization_id'], actor)]
            apps = [portal.app_dto(db, a, identity, provider) for a in visible]
            users = [{'id': u['id'], 'name': u['name']} for u in portal.store.users(db)]
        return {'organizations': organizations, 'apps': apps, 'available_users': users, 'capabilities': {'can_create_organization': True, 'recent_verification_required': True}, 'notice': 'Organization app and identity boundaries are enforced. Existing demo resources can be shared across organizations; membership never grants access.'}

    @api.post('/api/developer/organizations', status_code=201)
    def create(body: OrganizationInput, identity=Depends(authenticated)):
        recent(identity)
        if len(body.name.strip()) < 2:
            raise HTTPException(422, 'Organization name needs at least two non-whitespace characters')
        portal, actor = api.state.developer, identity['user']['id']
        organization_id = 'org_' + secrets.token_hex(12)
        with portal.store.connection(write=True) as db:
            if db.execute('SELECT COUNT(*) FROM organizations WHERE created_by=?', (actor,)).fetchone()[0] >= 10:
                raise HTTPException(429, 'At most ten organizations per prototype identity')
            db.execute('INSERT INTO organizations VALUES (?,?,?,?)', (organization_id, body.name.strip(), actor, stamp()))
            db.execute('INSERT INTO organization_members VALUES (?,?,\'admin\')', (organization_id, actor))
            portal.store.audit(db, 'organization_created', actor, {'organization_id': organization_id})
            return portal.organization_dto(db, organization_id, actor)

    @api.post('/api/developer/organizations/{organization_id}/members')
    def add_member(organization_id: str, body: MemberInput, identity=Depends(authenticated)):
        recent(identity)
        portal, actor = api.state.developer, identity['user']['id']
        with portal.store.connection(write=True) as db:
            portal.require_member(db, organization_id, actor, {'admin'})
            if not db.execute('SELECT id FROM users WHERE id=?', (body.user_id,)).fetchone():
                raise HTTPException(404, 'Identity not found; onboard the identity before adding membership')
            old = portal.role(db, organization_id, body.user_id)
            if old == 'admin' and body.role != 'admin' and db.execute("SELECT COUNT(*) FROM organization_members WHERE organization_id=? AND role='admin'", (organization_id,)).fetchone()[0] <= 1:
                raise HTTPException(409, 'The last organization administrator cannot be demoted')
            if not old and db.execute('SELECT COUNT(*) FROM organization_members WHERE organization_id=?', (organization_id,)).fetchone()[0] >= 100:
                raise HTTPException(429, 'Prototype organization member limit reached')
            db.execute('INSERT INTO organization_members VALUES (?,?,?) ON CONFLICT(organization_id,user_id) DO UPDATE SET role=excluded.role', (organization_id, body.user_id, body.role))
            portal.store.audit(db, 'organization_membership_changed', actor, {'organization_id': organization_id, 'user_id': body.user_id, 'role': body.role})
            return portal.organization_dto(db, organization_id, actor)

    @api.delete('/api/developer/organizations/{organization_id}/members/{user_id}')
    def remove_member(organization_id: str, user_id: str, identity=Depends(authenticated)):
        recent(identity)
        portal, actor = api.state.developer, identity['user']['id']
        with portal.store.connection(write=True) as db:
            portal.require_member(db, organization_id, actor, {'admin'})
            old = portal.role(db, organization_id, user_id)
            if not old:
                raise HTTPException(404, 'Member not found')
            if old == 'admin' and db.execute("SELECT COUNT(*) FROM organization_members WHERE organization_id=? AND role='admin'", (organization_id,)).fetchone()[0] <= 1:
                raise HTTPException(409, 'The last organization administrator cannot be removed')
            db.execute('DELETE FROM organization_members WHERE organization_id=? AND user_id=?', (organization_id, user_id))
            db.execute('DELETE FROM oauth_tokens WHERE user_id=? AND client_id IN (SELECT client_id FROM oauth_apps WHERE organization_id=?)', (user_id, organization_id))
            db.execute('UPDATE oauth_codes SET consumed=1 WHERE user_id=? AND client_id IN (SELECT client_id FROM oauth_apps WHERE organization_id=?)', (user_id, organization_id))
            portal.store.audit(db, 'organization_member_removed', actor, {'organization_id': organization_id, 'user_id': user_id, 'app_tokens_revoked': True})
        return {'removed': True, 'organization_id': organization_id, 'user_id': user_id, 'tokens_revoked': True}

    @api.post('/api/developer/callback-check')
    def callback_check(body: CallbackInput, identity=Depends(authenticated)):
        from .oauth import valid_url
        valid = valid_url(body.redirect_uri, callback=True)
        parsed = urlsplit(body.redirect_uri) if valid else None
        origin = f'{parsed.scheme}://{parsed.netloc}' if parsed else None
        registered = None
        if body.client_id:
            with api.state.developer.store.connection() as db:
                application = db.execute('SELECT * FROM oauth_apps WHERE client_id=?', (body.client_id,)).fetchone()
                if not application:
                    raise HTTPException(404, 'Application not found')
                api.state.developer.require_app_manager(db, application, identity)
                registered = body.redirect_uri in api.state.oauth.app_dto(application)['redirect_uris'] and bool(application['active'])
        return {'valid': valid, 'registered': registered, 'origin': origin, 'development_only': bool(parsed and parsed.scheme == 'http'), 'checks': [
            {'name': 'Safe callback URL', 'passed': valid, 'message': 'Exact HTTPS or loopback HTTP; no wildcard, credentials, fragment or reserved OAuth parameters.'},
            {'name': 'Exact registration', 'passed': registered is True, 'message': 'Matches an active app callback.' if registered else 'Register this exact callback before starting sign-in.'},
        ], 'network_request_performed': False}
