const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character])
const icons = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  projects: '<path d="M3 7h7l2 2h9v11H3z"/><path d="M3 7V4h7l2 3"/>',
  reports: '<path d="M5 3h10l4 4v14H5z"/><path d="M14 3v5h5M8 12h8M8 16h5"/>',
  settings: '<path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
  shield: '<path d="M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/><path d="M8 12l3 3 5-6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
  chevron: '<path d="M9 5l7 7-7 7"/>',
  logout: '<path d="M9 3H4v18h5M10 12h10M16 8l4 4-4 4"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="M15 15l5 5"/>',
}
const icon = name => `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] || icons.overview}</svg>`
const logo = '<span class="orbit-mark" aria-hidden="true"><svg viewBox="0 0 32 32"><ellipse cx="16" cy="16" rx="13" ry="6" transform="rotate(-38 16 16)"/><ellipse cx="16" cy="16" rx="13" ry="6" transform="rotate(38 16 16)"/><circle cx="16" cy="16" r="3"/></svg></span><span>Orbit<span class="brand-detail">workspace</span></span>'
const themeButton = `<button class="icon-button theme-toggle" type="button" aria-label="Switch color theme" title="Switch color theme" aria-pressed="false">${icon('sun')}</button>`
function document(title, body, className = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="description" content="Orbit Workspace, a SaaS project dashboard connected to Adaptive IAM for sign-in and resource access."><title>${escape(title)} · Orbit Workspace</title><link rel="stylesheet" href="/assets/orbit.css"><script src="/assets/orbit.js" defer></script></head><body class="${className}"><a class="skip-link" href="#main">Skip to content</a>${body}</body></html>`
}
function publicHeader(signedIn) {
  return `<header class="public-header"><a class="brand" href="/" aria-label="Orbit Workspace home">${logo}</a><nav aria-label="Main navigation"><a href="/#product">Product</a><a href="/pricing">Plans</a><a href="/dashboard">Workspace</a></nav><div class="header-actions">${themeButton}<a class="button small" href="${signedIn ? '/dashboard' : '/login'}">${signedIn ? 'Open dashboard' : 'Sign in'}</a></div></header>`
}
function footer(consoleOrigin) {
  return `<footer class="public-footer"><span>Orbit Workspace / Local SaaS demonstration</span><a href="${escape(consoleOrigin)}">Open Adaptive IAM</a><span>Business data is illustrative. Identity and access checks are live.</span></footer>`
}
const sampleBadge = '<span class="sample-badge">Sample workspace</span>'
const projects = [
  { name: 'Springboard launch', description: 'Release the next customer workspace', team: 'Product', progress: 72, status: 'On track', date: '18 Oct', color: 'orange' },
  { name: 'Customer onboarding', description: 'Make the first five minutes feel clear', team: 'Experience', progress: 48, status: 'In review', date: '22 Oct', color: 'purple' },
  { name: 'Usage insights', description: 'Turn product events into useful reports', team: 'Engineering', progress: 91, status: 'On track', date: '25 Oct', color: 'blue' },
  { name: 'Workspace foundations', description: 'Simplify roles and project ownership', team: 'Platform', progress: 34, status: 'Planning', date: '30 Oct', color: 'green' },
]
function projectRows(full = false) {
  return projects.slice(0, full ? 4 : 3).map(project => `<tr data-project="${escape(`${project.name} ${project.team} ${project.status}`.toLowerCase())}"><td><span class="project-name"><span class="project-symbol ${project.color}">${project.name.charAt(0)}</span><span><strong>${project.name}</strong><small>${project.description}</small></span></span></td><td>${project.team}</td><td><span class="progress" aria-label="${project.progress}% complete"><span class="progress-track"><span class="fill progress-${project.progress}"></span></span><span>${project.progress}%</span></span></td><td><span class="status ${project.status === 'On track' ? 'positive' : ''}">${project.status}</span></td><td>${project.date}</td></tr>`).join('')
}
function projectTable(full = false) {
  return `<div class="table-scroll"><table class="project-table"><caption class="visually-hidden">Illustrative project list</caption><thead><tr><th scope="col">Project</th><th scope="col">Team</th><th scope="col">Progress</th><th scope="col">Status</th><th scope="col">Target</th></tr></thead><tbody>${projectRows(full)}</tbody></table></div><p class="filter-empty" hidden>No sample projects match. Try a different search.</p>`
}
function chart() {
  return `<svg class="delivery-chart" viewBox="0 0 600 180" role="img" aria-label="Illustrative completed tasks over four weeks: 24, 38, 31 and 56. This is sample data."><g class="chart-grid"><path d="M42 20h535M42 64h535M42 108h535M42 152h535"/></g><g class="chart-label"><text x="9" y="25">60</text><text x="9" y="69">40</text><text x="9" y="113">20</text><text x="9" y="157">0</text><text x="44" y="177">Week 1</text><text x="202" y="177">Week 2</text><text x="364" y="177">Week 3</text><text x="526" y="177">Week 4</text></g><path class="chart-area" d="M54 99L222 68L390 84L558 29V152H54Z"/><path class="chart-line" d="M54 99L222 68L390 84L558 29"/><g class="chart-dots"><circle cx="54" cy="99" r="4"/><circle cx="222" cy="68" r="4"/><circle cx="390" cy="84" r="4"/><circle cx="558" cy="29" r="5"/></g></svg>`
}

export function homePage({ signedIn, consoleOrigin }) {
  return document('Projects, with the right access', `${publicHeader(signedIn)}
    <main id="main" class="landing">
      <section class="hero">
        <div class="hero-copy">
          <p class="intro-line"><span class="live-dot"></span>Orbit project workspace</p>
          <h1>Your team’s work.<br>A clearer view.</h1>
          <p class="lead">Track projects, review milestones and open the reports you’re approved to see. Sign in once with Adaptive IAM.</p>
          <div class="hero-actions"><a class="button" href="${signedIn ? '/dashboard' : '/login'}">${signedIn ? 'Open dashboard' : 'Sign in with Adaptive IAM'}</a><a class="text-link" href="/pricing">View sample plans</a></div>
          <div class="identity-note">${icon('shield')}<span>Passwords are verified by IAM.<br>Report access needs a separate approved permission.</span></div>
        </div>
        <div class="hero-preview" aria-label="Sample project workspace preview">
          <div class="preview-toolbar"><strong>Workspace preview</strong>${sampleBadge}</div>
          <div class="preview-body">
            <div class="preview-heading"><h2>October delivery</h2><span class="pill">4 projects</span></div>
            <p class="muted">A sample of what your team sees after sign-in.</p>
            <div class="preview-stats"><div><strong>4</strong><span>Active projects</span></div><div><strong>149</strong><span>Completed tasks</span></div><div><strong>18 Oct</strong><span>Next milestone</span></div></div>
            <div class="preview-chart"><div class="section-heading"><strong>Completed tasks</strong><span>Sample / four weeks</span></div>${chart()}</div>
            <div class="preview-project"><span class="project-symbol orange">S</span><div><strong>Springboard launch</strong><span>Product team · 72% complete</span></div><span class="status positive">On track</span></div>
          </div>
          <div class="preview-foot">${icon('lock')}<span>Protected reports open only with a live IAM grant.</span></div>
        </div>
      </section>
      <section id="product" class="product-section">
        <div class="section-intro"><h2>A practical team workspace</h2><p>Explore sample business data with a working sign-in and permission flow.</p></div>
        <div class="product-features">
          <article>${icon('projects')}<h3>Projects at a glance</h3><p>Find a project by name, team or status. See progress and upcoming milestones in one place.</p></article>
          <article>${icon('reports')}<h3>Reports with approval</h3><p>Your signed-in identity is checked on each visit. Protected reports also require a current read grant.</p></article>
          <article>${icon('shield')}<h3>A separate identity provider</h3><p>IAM verifies your password and factors. Orbit stores its website tokens on the server.</p></article>
        </div>
      </section>
      <section class="landing-cta"><div><h2>Explore the connected workspace</h2><p>Sample projects. Real authentication and permission checks.</p></div><a class="button" href="${signedIn ? '/dashboard' : '/login'}">${signedIn ? 'Open dashboard' : 'Sign in with Adaptive IAM'}</a></section>
    </main>${footer(consoleOrigin)}`, 'public-page')
}
export function pricingPage({ signedIn, consoleOrigin }) {
  return document('Plans', `${publicHeader(signedIn)}<main id="main" class="plans-page"><div class="page-intro"><h1>Plans for your workspace</h1><p>Illustrative product plans. This research demonstration does not take payments or create subscriptions.</p></div><div class="plan-grid"><article class="plan"><h2>Starter</h2><p>Explore the core project workspace.</p><div class="plan-price">Free<span>sample plan</span></div><ul><li>Project overview</li><li>Team workspace</li><li>Adaptive IAM sign-in</li></ul><a class="button secondary" href="/login">Explore the demo</a></article><article class="plan featured"><span class="plan-note">For growing teams</span><h2>Team</h2><p>Coordinate projects and protected reports.</p><div class="plan-price">₹799<span>illustrative / member / month</span></div><ul><li>Everything in Starter</li><li>Protected reporting workflow</li><li>Human-reviewed access</li></ul><a class="button" href="/login">Explore the demo</a></article><article class="plan"><h2>Business</h2><p>Manage sign-in and access across applications.</p><div class="plan-price">Custom<span>illustrative plan</span></div><ul><li>Everything in Team</li><li>Organization app registration</li><li>Permission and session controls</li></ul><a class="button secondary" href="${escape(consoleOrigin)}">View IAM capabilities</a></article></div></main>${footer(consoleOrigin)}`, 'public-page')
}
function accessPanel(access, consoleOrigin, expanded = false) {
  const allowed = access.state === 'allowed'
  const title = allowed ? 'Report access is active' : access.state === 'locked' ? 'Report access needs approval' : 'Permission check unavailable'
  const detail = allowed ? 'Your active read grant was checked with IAM on this visit.' : access.state === 'locked' ? 'You are signed in. An approved research-vault read grant is still required.' : 'IAM could not confirm access. Protected content stays unavailable.'
  return `<section class="access-panel ${allowed ? 'access-allowed' : ''}"><div class="access-icon">${icon(allowed ? 'shield' : 'lock')}</div><div><h${expanded ? '2' : '3'}>${title}</h${expanded ? '2' : '3'}><p>${detail}</p>${expanded && allowed ? `<p class="grant-expiry">Grant expires ${escape(access.result.expiresAt)}</p>` : ''}</div><a class="button ${allowed ? '' : 'secondary'} small" href="${allowed ? '/reports' : escape(consoleOrigin)}">${allowed ? 'Open reports' : 'Review access in IAM'}</a></section>`
}
function dashboard(identity, access, consoleOrigin) {
  const first = escape((identity.name || identity.sub).split(' ')[0])
  return `<div class="workspace-heading"><div><p class="breadcrumb">Product workspace / Overview</p><h1>Welcome back, ${first}.</h1><p>Here’s the sample team’s progress this month.</p></div>${sampleBadge}</div>
    <section class="metric-strip" aria-label="Sample workspace metrics">
      <div><span>Active projects</span><strong>4</strong><span class="metric-note">Across 4 teams</span></div>
      <div><span>Completed tasks</span><strong>149</strong><span class="metric-note">Sample October total</span></div>
      <div><span>Projects on track</span><strong>2 of 4</strong><span class="metric-note">From the project list</span></div>
      <div><span>Next milestone</span><strong>18 Oct</strong><span class="metric-note">Springboard launch</span></div>
    </section>
    <div class="workspace-grid">
      <section class="delivery-panel"><div class="section-heading"><div><h2>Delivery overview</h2><p>Completed tasks in the sample workspace</p></div><span class="pill">4 weeks</span></div>${chart()}<div class="chart-summary"><span><i></i>Completed tasks</span><span>Sample data</span></div></section>
      <section class="milestone-panel"><div class="section-heading"><h2>Upcoming milestones</h2><span class="muted">October</span></div>
        <div class="milestone featured-milestone"><div class="milestone-date"><strong>18</strong><span>Oct</span></div><div><h3>Springboard launch</h3><p>Product review and release</p><span class="status positive">On track</span></div></div>
        <div class="milestone"><div class="milestone-date"><strong>22</strong><span>Oct</span></div><div><h3>Onboarding review</h3><p>Experience team</p></div></div>
        <div class="milestone"><div class="milestone-date"><strong>25</strong><span>Oct</span></div><div><h3>Usage insights</h3><p>Engineering team</p></div></div>
      </section>
    </div>
    <section class="projects-panel"><div class="section-heading"><div><h2>Projects in focus</h2><p>Progress, owners and target dates</p></div><a class="text-link" href="/projects">View all projects ${icon('chevron')}</a></div>${projectTable()}</section>
    ${accessPanel(access, consoleOrigin)}<p class="data-note">Projects, dates and charts are sample business data. Your identity and report permission status are checked with IAM.</p>`
}
function projectsView(access, consoleOrigin) {
  return `<div class="workspace-heading"><div><p class="breadcrumb">Workspace / Projects</p><h1>Projects</h1><p>Find the team, progress and next milestone for each sample project.</p></div>${sampleBadge}</div><div class="project-controls"><label class="search-field">${icon('search')}<span class="visually-hidden">Search sample projects</span><input id="project-search" type="search" placeholder="Search projects or teams" maxlength="100"></label><label class="filter-field"><span>Status</span><select id="project-status"><option value="">All statuses</option><option value="on track">On track</option><option value="in review">In review</option><option value="planning">Planning</option></select></label><p id="project-count" aria-live="polite">4 sample projects</p></div><section class="projects-panel">${projectTable(true)}</section>${accessPanel(access, consoleOrigin)}<p class="data-note">This project list is illustrative. Search and filters run locally; no business records are created or changed.</p>`
}
function reportsView(access) {
  return `<div class="workspace-heading"><div><p class="breadcrumb">Workspace / Protected reports</p><h1>Protected reports</h1><p>Protected research material, opened with your approved read permission.</p></div><span class="verified-badge">${icon('shield')}Live access confirmed</span></div><section class="report-meta"><div><span>Resource</span><strong>${escape(access.result.resourceId)}</strong></div><div><span>Permission</span><strong>${escape(access.result.scope)}</strong></div><div><span>Grant expires</span><strong>${escape(access.result.expiresAt)}</strong></div></section><article class="protected-report"><div class="section-heading"><h2>Adaptive access evidence</h2><span class="pill">Research prototype</span></div><p>This protected record demonstrates a separate SaaS website enforcing the IAM provider’s resource decision before returning content.</p><div class="report-findings"><section><h3>Authentication</h3><p>A signed identity and provider userinfo establish the account behind the website session.</p></section><section><h3>Authorization</h3><p>An active, human-approved read grant for research-vault is required. Sign-in alone cannot open this report.</p></section><section><h3>Continuous checks</h3><p>The website asks IAM again on every report visit. Revoked grants, expired sessions and unavailable checks deny the protected record.</p></section></div><div class="report-boundary">Research boundary: business figures elsewhere are sample data. This record demonstrates live access enforcement, not measured production security or real company reporting.</div></article><a class="text-link" href="/dashboard">Return to your dashboard</a>`
}
function settingsView(identity, session, consoleOrigin) {
  return `<div class="workspace-heading"><div><p class="breadcrumb">Workspace / Account</p><h1>Account settings</h1><p>This account was verified with Adaptive IAM on this visit.</p></div></div><section class="account-panel"><div class="account-avatar">${escape((identity.name || identity.sub).slice(0,1).toUpperCase())}</div><div><h2>${escape(identity.name || identity.sub)}</h2><p>Signed in with Adaptive IAM</p></div><dl class="account-details"><div><dt>Verified subject</dt><dd>${escape(identity.sub)}</dd></div><div><dt>Website session expires</dt><dd>${escape(new Date(session.expiresAt).toISOString())}</dd></div><div><dt>Protected report resource</dt><dd>research-vault</dd></div><div><dt>Access policy</dt><dd>Live read grant required for each report visit</dd></div></dl></section><section class="account-actions"><div><h2>Manage your sign-in and permissions</h2><p>Use IAM for authentication factors, access requests and session controls.</p></div><a class="button secondary" href="${escape(consoleOrigin)}">Open Adaptive IAM</a></section><section class="account-actions"><div><h2>End this website session</h2><p>Sign out removes this local session and attempts to revoke its provider token.</p></div><form method="post" action="/logout"><button class="button secondary" type="submit">Sign out</button></form></section>`
}
export function workspacePage({ view, identity, session, access, consoleOrigin }) {
  const sections = [['dashboard','overview','Overview'],['projects','projects','Projects'],['reports','reports','Protected reports'],['settings','settings','Account']]
  const body = view === 'projects' ? projectsView(access, consoleOrigin) : view === 'reports' ? reportsView(access) : view === 'settings' ? settingsView(identity, session, consoleOrigin) : dashboard(identity, access, consoleOrigin)
  return document(sections.find(item => item[0] === view)?.[2] || 'Workspace', `<div class="app-shell"><aside class="sidebar"><a class="brand" href="/" aria-label="Orbit Workspace home">${logo}</a><div class="workspace-switch"><span class="workspace-emblem">O</span><span><strong>Product workspace</strong><small>Demonstration</small></span></div><nav class="app-nav" aria-label="Workspace navigation">${sections.map(([path,name,label])=>`<a class="${path === view ? 'active' : ''}" href="/${path}" ${path === view ? 'aria-current="page"' : ''}>${icon(name)}<span>${label}</span>${path === 'reports' ? icon('lock') : ''}</a>`).join('')}</nav><div class="sidebar-bottom"><div class="provider-note">${icon('shield')}<div><strong>Connected to Adaptive IAM</strong><span>Identity and report access</span></div></div><a class="text-link" href="${escape(consoleOrigin)}">Manage access ${icon('chevron')}</a></div></aside><div class="workspace-main"><header class="workspace-header"><a class="mobile-brand brand" href="/">${logo}</a><span class="workspace-location">Product workspace</span><div class="header-actions">${themeButton}<span class="identity-chip"><span class="avatar">${escape((identity.name || identity.sub).slice(0,1).toUpperCase())}</span><span>${escape(identity.name || identity.sub)}</span></span><form action="/logout" method="post"><button type="submit" class="icon-button" aria-label="Sign out" title="Sign out">${icon('logout')}</button></form></div></header><main id="main" class="workspace-content">${body}</main><footer class="workspace-footer"><span>Orbit Workspace</span><span>Authentication and report access checked by Adaptive IAM</span></footer></div></div>`, 'workspace-page')
}
export function errorPage({ status, code, consoleOrigin }) {
  const denied = status === 403
  const title = status === 401 ? 'Sign in to continue' : denied ? 'Report access needs approval' : 'Access could not be confirmed'
  const detail = status === 401 ? 'Your website session is missing, expired or no longer valid. Sign in to establish your identity again.' : denied ? 'Your identity is signed in, but protected reports need a separate human-approved read grant for research-vault.' : 'The IAM service could not complete this check. Try again when it is available.'
  return document('Access status', `${publicHeader(false)}<main id="main" class="error-page"><div class="error-symbol">${icon(denied ? 'lock' : 'shield')}</div><p class="breadcrumb">Workspace access</p><h1>${title}</h1><p>${detail}</p><div class="error-actions"><a class="button" href="${status === 401 ? '/login' : denied ? escape(consoleOrigin) : '/dashboard'}">${status === 401 ? 'Sign in with Adaptive IAM' : denied ? 'Review access in IAM' : 'Try again'}</a><a class="button secondary" href="${denied ? '/dashboard' : '/'}">${denied ? 'Back to dashboard' : 'Back to Orbit'}</a></div><p class="error-code">Status: ${escape(status)} / ${escape(code)}</p><div class="error-boundary">Protected records are returned only after the server confirms an active permission.</div></main>${footer(consoleOrigin)}`, 'public-page')
}
