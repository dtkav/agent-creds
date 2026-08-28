package api

import "net/http"

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	dashboardSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(dashboardHTML))
	}
}

func (s *Server) handleDashboardCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	dashboardSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write([]byte(dashboardCSS))
}

func (s *Server) handleDashboardJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	dashboardSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(dashboardJS))
}

func dashboardSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "publickey-credentials-get=(self)")
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>vault operations</title>
  <link rel="stylesheet" href="/assets/vault.css">
</head>
<body>
  <header class="topbar">
    <div class="brand"><span class="vault-mark" aria-hidden="true">V</span><strong>Vault</strong><span class="environment">local</span></div>
    <div class="top-actions">
      <span id="connection" class="connection"><i></i><span>connecting</span></span>
      <span id="identity" class="identity hidden"></span>
      <button id="logout" class="header-button hidden" type="button">Sign out</button>
    </div>
  </header>

  <main>
    <section id="loginView" class="auth-view">
      <div class="auth-logo"><span class="vault-mark" aria-hidden="true">V</span><strong>Vault</strong></div>
      <h1>Credential Vault</h1>
      <p>Sign in to inspect credential metadata and operational activity. Secret material is never returned by this interface.</p>
      <form id="loginForm"><button id="loginButton" type="submit">Sign in with a passkey</button></form>
      <div id="loginError" class="error hidden" role="alert"></div>
      <p class="auth-note">WebAuthn origin: <code>http://localhost:8033</code></p>
      <button id="enrollButton" class="link-button" type="button">Enroll a new passkey</button>
    </section>

    <section id="dashboard" class="app-shell hidden">
      <aside class="sidebar">
        <div class="sidebar-context"><span>Credential Vault</span><strong>local</strong></div>
        <nav aria-label="Vault sections">
          <p>Vault</p>
          <button class="nav-item active" type="button" data-view-target="credentials">Credentials</button>
          <button class="nav-item" type="button" data-view-target="mints">Capability mints</button>
          <button class="nav-item" type="button" data-view-target="tokens">Saved capabilities</button>
          <p>Monitoring</p>
          <button class="nav-item" type="button" data-view-target="audit">Authorization log</button>
        </nav>
        <div class="sidebar-meta"><span>RP ID</span><code>localhost</code><span>Secrets</span><code>redacted</code></div>
      </aside>

      <div class="workspace">
        <header class="workspace-header">
          <div><p>Credential Vault / <span id="viewCrumb">Credentials</span></p><h1 id="viewTitle">Credentials</h1><div id="viewDescription">Configured providers, redacted sources, policies, and authorized scope.</div></div>
          <label class="control">Lookback
            <select id="lookback"><option value="900">15 minutes</option><option value="3600" selected>1 hour</option><option value="21600">6 hours</option><option value="86400">24 hours</option><option value="604800">7 days</option></select>
          </label>
        </header>

        <dl class="status-strip" aria-label="Vault summary">
          <div><dt>Credentials</dt><dd id="credentialCount">—</dd><small id="generation">active config</small></div>
          <div><dt>Active capabilities</dt><dd id="activeMintCount">—</dd><small>unexpired in window</small></div>
          <div><dt>Mints</dt><dd id="mintCount">—</dd><small id="mintWindow">1 hour</small></div>
          <div><dt>Requests</dt><dd id="requestCount">—</dd><small id="denialCount">— denied</small></div>
        </dl>

        <section class="data-view" data-view="credentials">
          <div class="toolbar"><label class="search-label">Filter <input id="credentialSearch" class="search" type="search" placeholder="Filter by path, provider, policy, or host" aria-label="Filter credentials"></label></div>
          <div class="table-wrap"><table class="credential-table"><thead><tr><th class="expand-heading"><span class="visually-hidden">Details</span></th><th>Credential</th><th>Provider</th><th>Delivery</th><th>Targets</th><th>Policy</th></tr></thead><tbody id="credentialBody"></tbody></table></div>
        </section>

        <section class="data-view hidden" data-view="mints">
          <div class="table-wrap"><table><thead><tr><th>Issued</th><th>Status</th><th>Actor / source</th><th>Target</th><th>Credential / ID</th><th>Expires</th></tr></thead><tbody id="mintsBody"></tbody></table></div>
        </section>

        <section class="data-view hidden" data-view="tokens">
          <div class="table-wrap"><table><thead><tr><th>Capability ID</th><th>Description</th><th>Created</th></tr></thead><tbody id="tokensBody"></tbody></table></div>
        </section>

        <section class="data-view hidden" data-view="audit">
          <div class="toolbar"><label class="control">Decision <select id="decisionFilter" aria-label="Filter authorization decisions"><option value="">All decisions</option><option value="allow">Allowed</option><option value="deny">Denied</option></select></label></div>
          <div class="table-wrap"><table><thead><tr><th>Time</th><th>Decision</th><th>Request</th><th>Capability ID</th><th>Reason</th></tr></thead><tbody id="auditBody"></tbody></table></div>
        </section>

        <footer><span id="lastUpdated">Waiting for first refresh</span><span>Secret values remain server-side</span></footer>
      </div>
    </section>
  </main>
  <script src="/assets/vault.js" defer></script>
</body>
</html>`

const dashboardCSS = `
:root { color-scheme:light; --bg:#f5f5f3; --surface:#fff; --header:#1d1f21; --sidebar:#f0f1f2; --border:#d5d7d9; --border-strong:#b8bdc2; --text:#1f2124; --muted:#656a70; --dim:#8b9198; --action:#106da0; --action-hover:#0a547e; --active:#e0e3e6; --green:#16835d; --amber:#b7791f; --red:#c23b3b; --purple:#6f4ba1; --mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace; --sans:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; background:var(--bg); color:var(--text); font:14px/1.45 var(--sans); }
button,input,select { font:inherit; }.hidden { display:none !important; }
.topbar { position:sticky; top:0; z-index:20; height:56px; padding:0 20px; display:flex; align-items:center; justify-content:space-between; color:#fff; background:var(--header); border-bottom:1px solid #000; }
.brand,.top-actions,.connection,.auth-logo { display:flex; align-items:center; }.brand { gap:10px; }.brand strong { font-size:15px; }.vault-mark { width:28px; height:28px; display:grid; place-items:center; color:#111; background:#f7d154; font:700 14px/1 var(--sans); clip-path:polygon(50% 0,100% 20%,85% 100%,15% 100%,0 20%); }.environment { margin-left:6px; padding-left:14px; color:#b7bbc0; border-left:1px solid #555; font-size:12px; }.top-actions { gap:16px; }.connection { gap:7px; color:#c6c9cc; font-size:12px; }.connection i { width:8px; height:8px; border-radius:50%; background:var(--amber); }.connection.live i { background:#42c88a; }.connection.down i { background:#ef6b6b; }.identity { color:#d8dadd; font:12px var(--mono); }.header-button { padding:6px 10px; color:#fff; background:transparent; border:1px solid #686c70; border-radius:2px; cursor:pointer; }.header-button:hover { background:#303336; }
main { min-height:calc(100vh - 56px); }
.auth-view { width:min(460px,calc(100% - 40px)); margin:0 auto; padding-top:13vh; }.auth-logo { gap:10px; margin-bottom:38px; }.auth-logo strong { font-size:18px; }.auth-view h1 { margin:0 0 8px; font-size:28px; font-weight:600; letter-spacing:-.02em; }.auth-view>p { color:var(--muted); }.auth-view form { margin-top:26px; }.auth-view form button { width:100%; padding:10px 16px; color:#fff; background:var(--action); border:1px solid var(--action); border-radius:2px; font-weight:600; cursor:pointer; }.auth-view form button:hover { background:var(--action-hover); }.auth-view form button:disabled { color:var(--muted); background:#e5e7e9; border-color:var(--border); cursor:wait; }.auth-note { margin:18px 0 5px; font-size:12px; }.auth-note code { color:var(--text); font-family:var(--mono); }.link-button { padding:0; color:var(--action); background:none; border:0; cursor:pointer; }.link-button:hover { color:var(--action-hover); text-decoration:underline; }.error { margin-top:16px; padding:10px 12px; color:#7c2020; background:#fff1f0; border:1px solid #e7b4b0; border-radius:2px; }
.app-shell { min-height:calc(100vh - 56px); display:grid; grid-template-columns:236px minmax(0,1fr); }.sidebar { position:sticky; top:56px; height:calc(100vh - 56px); display:flex; flex-direction:column; background:var(--sidebar); border-right:1px solid var(--border); }.sidebar-context { min-height:73px; padding:15px 18px; display:flex; flex-direction:column; justify-content:center; border-bottom:1px solid var(--border); }.sidebar-context span { color:var(--muted); font-size:11px; }.sidebar-context strong { margin-top:2px; font-size:14px; }.sidebar nav { padding:15px 10px; }.sidebar nav p { margin:12px 9px 5px; color:var(--dim); font-size:10px; font-weight:600; letter-spacing:.08em; text-transform:uppercase; }.nav-item { width:100%; padding:8px 10px; color:#35383c; background:transparent; border:0; border-left:3px solid transparent; text-align:left; cursor:pointer; }.nav-item:hover { color:var(--text); background:#e7e9eb; }.nav-item.active { color:var(--text); background:var(--active); border-left-color:var(--purple); font-weight:600; }.sidebar-meta { margin-top:auto; padding:16px 18px; display:grid; grid-template-columns:auto 1fr; gap:5px 10px; color:var(--dim); border-top:1px solid var(--border); font-size:10px; }.sidebar-meta code { color:var(--muted); font-family:var(--mono); }
.workspace { min-width:0; padding:0 32px 40px; }.workspace-header { min-height:122px; display:flex; align-items:center; justify-content:space-between; gap:30px; }.workspace-header p { margin:0 0 6px; color:var(--muted); font-size:12px; }.workspace-header p span { color:var(--text); }.workspace-header h1 { margin:0; font-size:28px; line-height:1.15; letter-spacing:-.025em; }.workspace-header h1+div { margin-top:7px; color:var(--muted); font-size:13px; }.control { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:12px; }.control select,.search { color:var(--text); background:var(--surface); border:1px solid var(--border-strong); border-radius:2px; outline:none; }.control select { min-width:128px; padding:7px 30px 7px 9px; }.control select:focus,.search:focus { border-color:var(--action); box-shadow:0 0 0 2px rgba(16,109,160,.14); }
.status-strip { margin:0 0 24px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); background:var(--surface); border:1px solid var(--border); }.status-strip>div { min-height:82px; padding:14px 16px; border-right:1px solid var(--border); }.status-strip>div:last-child { border-right:0; }.status-strip dt { color:var(--muted); font-size:11px; }.status-strip dd { margin:4px 0 1px; font-size:24px; font-weight:600; line-height:1.1; }.status-strip small { color:var(--dim); font-size:10px; }
.data-view { background:var(--surface); border:1px solid var(--border); }.toolbar { min-height:52px; padding:8px 12px; display:flex; align-items:center; justify-content:flex-end; background:#fafafa; border-bottom:1px solid var(--border); }.search-label { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:12px; }.search { width:340px; padding:7px 9px; }
.table-wrap { overflow:auto; }table { width:100%; border-collapse:collapse; table-layout:auto; }th { padding:9px 12px; color:#51565b; background:#f1f2f3; border-bottom:1px solid var(--border-strong); font-size:11px; font-weight:600; text-align:left; white-space:nowrap; }td { padding:11px 12px; color:#35383c; border-bottom:1px solid #e4e5e6; font-size:12px; vertical-align:top; }tbody tr:last-child td { border-bottom:0; }tbody tr:hover td { background:#f7f8f8; }.mono { font-family:var(--mono); }.nowrap { white-space:nowrap; }.sub,.datum { display:block; }.sub { margin-top:3px; color:var(--dim); font-size:10px; }.datum { max-width:440px; overflow-wrap:anywhere; }.datum+.datum { margin-top:3px; }.secret { color:#735f17; }.policy { color:var(--purple); }.provider { color:var(--action); font-weight:600; }.empty { padding:28px 12px; color:var(--dim); text-align:center; }.state { white-space:nowrap; font-size:10px; font-weight:600; text-transform:uppercase; }.state::before { content:''; width:7px; height:7px; margin-right:6px; display:inline-block; border-radius:50%; background:currentColor; }.state.active,.state.allow { color:var(--green); }.state.expired { color:var(--dim); }.state.deny { color:var(--red); }.reason { max-width:520px; color:var(--muted); overflow-wrap:anywhere; }.request { min-width:260px; }.request b { margin-right:8px; color:var(--action); font-size:10px; }
.visually-hidden { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
.credential-table { min-width:820px; table-layout:fixed; }.credential-table .expand-heading { width:40px; padding:0; }.credential-table th:nth-child(2) { width:24%; }.credential-table th:nth-child(3) { width:10%; }.credential-table th:nth-child(4) { width:22%; }.credential-table th:nth-child(5) { width:27%; }.credential-table th:nth-child(6) { width:17%; }.credential-summary td { height:56px; padding-top:8px; padding-bottom:8px; vertical-align:middle; }.credential-summary td:first-child { padding:0; }.credential-summary.expanded td { background:#e8e8e8; border-bottom-color:transparent; }.credential-name,.summary-primary { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }.summary-primary { color:var(--text); }.summary-meta { display:block; margin-top:2px; color:var(--dim); font-size:10px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }.policy.none { color:var(--dim); }.credential-toggle { width:40px; height:40px; padding:0; display:grid; place-items:center; color:var(--text); background:transparent; border:0; cursor:pointer; }.credential-toggle:hover,.credential-toggle:focus-visible { background:#d9d9d9; outline:2px solid var(--action); outline-offset:-2px; }.credential-toggle svg { width:16px; height:16px; fill:currentColor; transition:transform .12s ease; }.credential-toggle[aria-expanded="true"] svg { transform:rotate(90deg); }.credential-detail td { padding:0; background:#f4f4f4; border-bottom:1px solid var(--border-strong); }.credential-detail:hover td { background:#f4f4f4; }.credential-detail-body { max-height:min(52vh,520px); padding:18px 24px 24px 48px; overflow:auto; border-top:1px solid #d8d8d8; }.credential-detail-layout { display:grid; grid-template-columns:minmax(280px,2fr) minmax(420px,3fr); gap:32px; }.detail-section h3 { margin:0 0 12px; color:#45494e; font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; }.detail-section+.detail-section { padding-left:32px; border-left:1px solid var(--border); }.detail-line { min-height:26px; display:grid; grid-template-columns:minmax(70px,auto) 14px minmax(0,1fr); align-items:start; gap:6px; }.detail-line code,.delivery-line code,.host-line code,.endpoint-paths code { font-family:var(--mono); font-size:11px; }.detail-line code:first-child { color:var(--muted); }.detail-line .arrow { color:var(--dim); text-align:center; }.pointer-reference { color:#735f17; overflow-wrap:anywhere; }.delivery-line,.host-line { margin-top:10px; color:var(--muted); font-size:11px; }.delivery-line code,.host-line code { margin-left:7px; color:var(--text); }.endpoint-list { margin-top:12px; border-top:1px solid var(--border); }.endpoint-definition { padding:9px 0; display:grid; grid-template-columns:72px minmax(0,1fr); gap:10px; border-bottom:1px solid #dedede; }.endpoint-methods { display:flex; align-items:flex-start; flex-wrap:wrap; gap:3px; }.method { padding:2px 4px; color:var(--action); background:#d9edf7; font:600 9px var(--mono); }.endpoint-paths code { display:block; color:var(--text); overflow-wrap:anywhere; }.endpoint-paths code+code { margin-top:3px; }.endpoint-description { margin-top:5px; color:var(--muted); font-size:10px; }.detail-empty { margin:0; color:var(--dim); font-size:11px; }
footer { min-height:50px; display:flex; align-items:center; justify-content:space-between; color:var(--dim); font-size:10px; }
@media (max-width:900px) { .app-shell { grid-template-columns:190px minmax(0,1fr); }.workspace { padding-left:20px; padding-right:20px; }.status-strip { grid-template-columns:repeat(2,1fr); }.status-strip>div:nth-child(2) { border-right:0; }.status-strip>div:nth-child(-n+2) { border-bottom:1px solid var(--border); }.search { width:240px; }.credential-detail-layout { grid-template-columns:1fr; gap:20px; }.detail-section+.detail-section { padding:20px 0 0; border-top:1px solid var(--border); border-left:0; } }
@media (max-width:680px) { .environment,.identity { display:none; }.app-shell { display:block; }.sidebar { position:static; width:100%; height:auto; border-right:0; border-bottom:1px solid var(--border); }.sidebar-context,.sidebar-meta,.sidebar nav p { display:none; }.sidebar nav { padding:6px; display:flex; overflow:auto; }.nav-item { width:auto; flex:none; border-left:0; border-bottom:3px solid transparent; }.nav-item.active { border-left:0; border-bottom-color:var(--purple); }.workspace { padding:0 12px 30px; }.workspace-header { min-height:145px; align-items:flex-start; flex-direction:column; justify-content:center; gap:16px; }.workspace-header .control { width:100%; justify-content:space-between; }.status-strip dd { font-size:20px; }.toolbar { align-items:stretch; }.search-label { width:100%; }.search { width:100%; } }
@media (max-width:420px) { .topbar { padding:0 12px; }.connection span { display:none; }.status-strip>div { padding:11px; }footer { align-items:flex-start; flex-direction:column; justify-content:center; gap:3px; } }
`

const dashboardJS = `
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const state = { token: sessionStorage.getItem('vault.session') || '', user: sessionStorage.getItem('vault.user') || '', view: sessionStorage.getItem('vault.view') || 'credentials', inventory: null, mints: [], audit: [], tokens: [], expandedCredentials: new Set(), timer: null, refreshing: false };
  const views = {
    credentials: { title: 'Credentials', description: 'Configured providers, redacted sources, policies, and authorized scope.' },
    mints: { title: 'Capability mints', description: 'Issuance history and capabilities that are still active in the selected window.' },
    tokens: { title: 'Saved capabilities', description: 'Named capabilities available to the authenticated identity.' },
    audit: { title: 'Authorization log', description: 'Recent allow and deny decisions at the credential boundary.' }
  };
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const array = (value) => Array.isArray(value) ? value : [];
  const when = (value) => { const d = new Date(value); return Number.isNaN(d.valueOf()) ? '—' : new Intl.DateTimeFormat(undefined,{hour:'numeric',minute:'2-digit',second:'2-digit'}).format(d); };
  const dateTime = (value) => { const d = new Date(value); return Number.isNaN(d.valueOf()) ? '—' : new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}).format(d); };
  const ago = (value) => { const seconds = Math.round((new Date(value).valueOf()-Date.now())/1000); const abs=Math.abs(seconds); const unit=abs<60?'second':abs<3600?'minute':abs<86400?'hour':'day'; const divisor=unit==='second'?1:unit==='minute'?60:unit==='hour'?3600:86400; return new Intl.RelativeTimeFormat(undefined,{numeric:'auto'}).format(Math.round(seconds/divisor),unit); };
  const buffer = (text) => { const base=text.replace(/-/g,'+').replace(/_/g,'/'); const binary=atob(base+'='.repeat((4-base.length%4)%4)); return Uint8Array.from(binary,c=>c.charCodeAt(0)).buffer; };
  const base64 = (value) => { if (!value) return ''; const bytes=new Uint8Array(value); let binary=''; bytes.forEach(byte=>binary+=String.fromCharCode(byte)); return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };

  function connection(kind, label) { const node=$('connection'); node.className='connection '+kind; node.querySelector('span').textContent=label; }
  function showLogin(message='') { clearInterval(state.timer); state.timer=null; $('dashboard').classList.add('hidden'); $('loginView').classList.remove('hidden'); $('identity').classList.add('hidden'); $('logout').classList.add('hidden'); if(message){$('loginError').textContent=message;$('loginError').classList.remove('hidden');} connection('','authentication required'); }
  function showView(name) {
    if(!views[name]) name='credentials';
    state.view=name; sessionStorage.setItem('vault.view',name);
    document.querySelectorAll('[data-view]').forEach(node=>node.classList.toggle('hidden',node.dataset.view!==name));
    document.querySelectorAll('[data-view-target]').forEach(node=>node.classList.toggle('active',node.dataset.viewTarget===name));
    $('viewCrumb').textContent=views[name].title; $('viewTitle').textContent=views[name].title; $('viewDescription').textContent=views[name].description;
  }
  function showDashboard() { $('loginView').classList.add('hidden'); $('dashboard').classList.remove('hidden'); $('identity').textContent=state.user; $('identity').classList.remove('hidden'); $('logout').classList.remove('hidden'); showView(state.view); }

  async function request(path, options={}) {
    const headers=new Headers(options.headers||{}); if(state.token) headers.set('Authorization','Bearer '+state.token); if(options.body) headers.set('Content-Type','application/json');
    const response=await fetch(path,{...options,headers,cache:'no-store'});
    if(response.status===401 && state.token){ sessionStorage.removeItem('vault.session'); state.token=''; showLogin('Your Vault session expired. Authenticate again.'); throw new Error('session expired'); }
    const body=response.status===204?null:await response.json().catch(()=>null); if(!response.ok) throw new Error(body?.error||('Request failed ('+response.status+')')); return body;
  }

  async function authenticate() {
    if(!window.PublicKeyCredential) throw new Error('This browser does not support passkeys.');
    const challenge=await request('/api/passkeys/authenticate/begin',{method:'POST',body:'{}'});
    const publicKey=challenge.options.publicKey; publicKey.challenge=buffer(publicKey.challenge); publicKey.allowCredentials=array(publicKey.allowCredentials).map(item=>({...item,id:buffer(item.id)}));
    const assertion=await navigator.credentials.get({publicKey});
    const response={id:assertion.id,rawId:base64(assertion.rawId),type:assertion.type,authenticatorAttachment:assertion.authenticatorAttachment||undefined,clientExtensionResults:assertion.getClientExtensionResults(),response:{authenticatorData:base64(assertion.response.authenticatorData),clientDataJSON:base64(assertion.response.clientDataJSON),signature:base64(assertion.response.signature),userHandle:base64(assertion.response.userHandle)}};
    const result=await request('/api/passkeys/authenticate/finish',{method:'POST',body:JSON.stringify({sessionId:challenge.sessionId,response})});
    state.token=result.sessionToken; state.user=result.username||''; sessionStorage.setItem('vault.session',state.token); sessionStorage.setItem('vault.user',state.user);
  }

  function query() { const since=new Date(Date.now()-Number($('lookback').value)*1000).toISOString(); const decision=$('decisionFilter').value; return {since,audit:'/api/audit?limit=250&since='+encodeURIComponent(since)+(decision?'&decision='+decision:''),mints:'/api/mints?limit=250&since='+encodeURIComponent(since)}; }
  async function refresh() {
    if(state.refreshing||!state.token) return; state.refreshing=true; connection('','refreshing');
    try { const q=query(); const [inventory,mints,audit,tokens]=await Promise.all([request('/api/inventory'),request(q.mints),request(q.audit),request('/api/tokens')]); state.inventory=inventory;state.mints=array(mints);state.audit=array(audit);state.tokens=array(tokens);render();connection('live','live');$('lastUpdated').textContent='Updated '+new Date().toLocaleTimeString(); }
    catch(error){ if(state.token){connection('down','retrying');$('lastUpdated').textContent='Refresh failed: '+error.message;} }
    finally { state.refreshing=false; }
  }

  function countLabel(count, singular) { return count+' '+singular+(count===1?'':'s'); }
  function credentialDetail(c) {
    const refs=array(c.secretRefs); const environments=array(c.environment); const hosts=array(c.hosts); const endpoints=array(c.endpoints);
    const pointers=refs.length?refs.map(ref=>'<div class="detail-line"><code>'+esc(ref.field)+'</code><span class="arrow">→</span><code class="pointer-reference">'+esc(ref.reference)+'</code></div>').join(''):'<p class="detail-empty">Inline value; content is redacted.</p>';
    const delivery=environments.length?'<div class="delivery-line">Delivered as '+environments.map(name=>'<code>'+esc(name)+'</code>').join(' ')+'</div>':'<div class="delivery-line">No environment delivery declared.</div>';
    const hostLine=hosts.length?'<div class="host-line">Hosts '+hosts.map(host=>'<code>'+esc(host)+'</code>').join(' ')+'</div>':'<div class="host-line">No host restriction declared.</div>';
    const rules=endpoints.length?'<div class="endpoint-list">'+endpoints.map(endpoint=>{ const methods=array(endpoint.methods); const paths=array(endpoint.paths); return '<div class="endpoint-definition"><div class="endpoint-methods">'+(methods.length?methods.map(method=>'<span class="method">'+esc(method)+'</span>').join(''):'<span class="method">ANY</span>')+'</div><div class="endpoint-paths">'+(paths.length?paths.map(path=>'<code>'+esc(path)+'</code>').join(''):'<code>/**</code>')+(endpoint.description?'<div class="endpoint-description">'+esc(endpoint.description)+'</div>':'')+'</div></div>'; }).join('')+'</div>':'<p class="detail-empty">No path rules declared.</p>';
    return '<div class="credential-detail-body"><div class="credential-detail-layout"><section class="detail-section"><h3>Secret pointers</h3>'+pointers+delivery+'</section><section class="detail-section"><h3>Authorized scope</h3>'+hostLine+rules+'</section></div></div>';
  }
  function renderCredentials() {
    const needle=$('credentialSearch').value.trim().toLowerCase(); const credentials=array(state.inventory?.credentials).filter(c=>!needle||JSON.stringify(c).toLowerCase().includes(needle)); const policies=new Map(array(state.inventory?.policies).map(p=>[p.name,p.type]));
    if(!credentials.length){$('credentialBody').innerHTML='<tr><td colspan="6" class="empty">No matching credentials.</td></tr>';return;}
    $('credentialBody').innerHTML=credentials.map((c,index)=>{ const refs=array(c.secretRefs); const environments=array(c.environment); const hosts=array(c.hosts); const endpoints=array(c.endpoints); const expanded=state.expandedCredentials.has(c.name); const routeCount=endpoints.reduce((count,endpoint)=>count+Math.max(1,array(endpoint.methods).length)*Math.max(1,array(endpoint.paths).length),0); const deliveryPrimary=environments[0]||'provider-managed'; const deliveryMeta=[environments.length>1?countLabel(environments.length,'variable'):'',countLabel(refs.length,'pointer')].filter(Boolean).join(' · '); const targetPrimary=hosts[0]||'unrestricted'; const targetMeta=[hosts.length>1?'+'+(hosts.length-1)+' hosts':'',routeCount?countLabel(routeCount,'route'):'no path rules'].filter(Boolean).join(' · '); const policyName=c.policy||'none'; const policyType=c.policy&&policies.get(c.policy)?policies.get(c.policy):''; const encoded=esc(encodeURIComponent(c.name)); const control='credential-detail-'+index; const summary='<tr class="credential-summary'+(expanded?' expanded':'')+'"><td><button class="credential-toggle" type="button" data-credential-toggle="'+encoded+'" aria-expanded="'+expanded+'" aria-controls="'+control+'" aria-label="'+(expanded?'Collapse ':'Expand ')+esc(c.name)+'"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5 7.1 13.6 12.7 8 7.1 2.4Z"/></svg></button></td><td><span class="credential-name mono" title="'+esc(c.name)+'">'+esc(c.name)+'</span></td><td class="provider">'+esc(c.type)+'</td><td><span class="summary-primary mono">'+esc(deliveryPrimary)+'</span><span class="summary-meta">'+esc(deliveryMeta)+'</span></td><td><span class="summary-primary mono">'+esc(targetPrimary)+'</span><span class="summary-meta">'+esc(targetMeta)+'</span></td><td><span class="policy '+(c.policy?'':'none')+'">'+esc(policyName)+'</span>'+(policyType?'<span class="summary-meta">'+esc(policyType)+'</span>':'')+'</td></tr>'; const detail='<tr class="credential-detail'+(expanded?'':' hidden')+'" id="'+control+'"><td colspan="6">'+(expanded?credentialDetail(c):'')+'</td></tr>'; return summary+detail; }).join('');
  }
  function renderMints() {
    if(!state.mints.length){$('mintsBody').innerHTML='<tr><td colspan="6" class="empty">No mints in this window.</td></tr>';return;}
    $('mintsBody').innerHTML=state.mints.map(m=>{ const active=!m.expiresAt||new Date(m.expiresAt)>new Date(); const actor=m.username||m.fingerprint||'unknown'; const target=array(m.hosts).join(', ')||m.name||'unrestricted'; const details=[array(m.methods).join(','),array(m.paths).join(', ')].filter(Boolean).join(' · '); return '<tr><td class="nowrap mono">'+when(m.timestamp)+'<span class="sub">'+ago(m.timestamp)+'</span></td><td><span class="state '+(active?'active':'expired')+'">'+(active?'active':'expired')+'</span>'+(m.attestation?'<span class="sub">attested</span>':'')+'</td><td>'+esc(actor)+'<span class="sub">'+esc(m.source)+'</span></td><td class="mono">'+esc(target)+(details?'<span class="sub">'+esc(details)+'</span>':'')+'</td><td class="mono">'+esc(m.credential||'—')+(m.tokenId?'<span class="sub">'+esc(m.tokenId)+'</span>':'')+'</td><td class="nowrap">'+(m.expiresAt?dateTime(m.expiresAt)+'<span class="sub">'+ago(m.expiresAt)+'</span>':'session-bound')+'</td></tr>'; }).join('');
  }
  function renderTokens() { if(!state.tokens.length){$('tokensBody').innerHTML='<tr><td colspan="3" class="empty">no saved capabilities for this identity</td></tr>';return;} $('tokensBody').innerHTML=[...state.tokens].sort((a,b)=>b.createdAt-a.createdAt).map(t=>'<tr><td class="mono">'+esc(t.id)+'</td><td>'+esc(t.description||'—')+'</td><td class="nowrap">'+esc(dateTime(t.createdAt*1000))+'</td></tr>').join(''); }
  function renderAudit() { if(!state.audit.length){$('auditBody').innerHTML='<tr><td colspan="5" class="empty">No authorization traffic in this window.</td></tr>';return;} $('auditBody').innerHTML=state.audit.map(a=>'<tr><td class="nowrap mono">'+when(a.timestamp)+'<span class="sub">'+ago(a.timestamp)+'</span></td><td><span class="state '+esc(a.decision)+'">'+esc(a.decision)+'</span></td><td class="request mono"><b>'+esc(a.method)+'</b>'+esc(a.host)+esc(a.path)+'</td><td class="mono">'+esc(a.token_id||'—')+'</td><td class="reason">'+esc(a.reason||'—')+'</td></tr>').join(''); }
  function render() { const now=Date.now(); const active=state.mints.filter(m=>!m.expiresAt||new Date(m.expiresAt).valueOf()>now).length; $('credentialCount').textContent=array(state.inventory?.credentials).length;$('generation').textContent='config generation '+(state.inventory?.generation??'—');$('activeMintCount').textContent=active;$('mintCount').textContent=state.mints.length;$('requestCount').textContent=state.audit.length;$('denialCount').textContent=state.audit.filter(a=>a.decision==='deny').length+' denied'; const selected=$('lookback').selectedOptions[0]?.textContent.toLowerCase()||'window';$('mintWindow').textContent=selected;renderCredentials();renderMints();renderTokens();renderAudit(); }

  $('loginForm').addEventListener('submit',async(event)=>{event.preventDefault();const button=$('loginButton');$('loginError').classList.add('hidden');button.disabled=true;button.textContent='Waiting for passkey…';try{await authenticate();showDashboard();await refresh();state.timer=setInterval(refresh,5000);}catch(error){$('loginError').textContent=error.name==='NotAllowedError'?'Passkey request was cancelled or timed out.':error.message;$('loginError').classList.remove('hidden');connection('down','authentication failed');}finally{button.disabled=false;button.textContent='Sign in with a passkey';}});
  $('enrollButton').addEventListener('click',()=>location.assign('/enroll'));
  $('logout').addEventListener('click',()=>{sessionStorage.removeItem('vault.session');sessionStorage.removeItem('vault.user');state.token='';state.user='';showLogin();});
  document.querySelectorAll('[data-view-target]').forEach(button=>button.addEventListener('click',()=>showView(button.dataset.viewTarget)));
  $('credentialBody').addEventListener('click',event=>{const button=event.target.closest('[data-credential-toggle]');if(!button)return;const name=decodeURIComponent(button.dataset.credentialToggle);if(state.expandedCredentials.has(name))state.expandedCredentials.delete(name);else state.expandedCredentials.add(name);renderCredentials();});
  $('lookback').addEventListener('change',refresh);$('decisionFilter').addEventListener('change',refresh);$('credentialSearch').addEventListener('input',renderCredentials);document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
  if(state.token){showDashboard();refresh();state.timer=setInterval(refresh,5000);}else{showLogin();fetch('/health',{cache:'no-store'}).then(r=>{if(r.ok)connection('','authentication required');}).catch(()=>connection('down','vault unavailable'));}
})();
`
