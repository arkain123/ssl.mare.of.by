/* ============ Issue: state ============ */
let sessionId = null;
const LS_KEY = 'ssl_tools_session_id';

function rememberSession(id) {
    try {
        if (id) localStorage.setItem(LS_KEY, id);
        else localStorage.removeItem(LS_KEY);
    } catch (e) {}
}

function readRememberedSession() {
    try { return localStorage.getItem(LS_KEY); }
    catch (e) { return null; }
}

const DNS_AUTO_CONFIG = {
    interval_ms: 30000,    // defaults - used until /api/config responds
    max_attempts: 240,
    start_delay_ms: 3000,
};

let _configPromise = null;

function loadAppConfig() {
    if (_configPromise) return _configPromise;
    _configPromise = fetch('/api/config')
        .then(r => r.json())
        .then(data => {
            if (data.dns_auto_interval_ms)   DNS_AUTO_CONFIG.interval_ms = data.dns_auto_interval_ms;
            if (data.dns_auto_max_attempts)  DNS_AUTO_CONFIG.max_attempts = data.dns_auto_max_attempts;
            if (data.dns_auto_start_delay_ms) DNS_AUTO_CONFIG.start_delay_ms = data.dns_auto_start_delay_ms;
            if (data.cert_expiry_warn_days)  window.CERT_EXPIRY_WARN_DAYS = data.cert_expiry_warn_days;
            console.log('[config] loaded:', data);
            return DNS_AUTO_CONFIG;
        })
        .catch(e => {
            console.warn('[config] fetch failed, using defaults:', e);
            return DNS_AUTO_CONFIG;
        });
    return _configPromise;
}

// Kick off immediately on page load
loadAppConfig();

/* ============ Issue: server-side DNS auto-check polling ============ */
// The actual checking runs in a background thread on the server.
// This module only polls /api/check_status to display progress and
// toggle the on/off flag via /api/check_auto_toggle.

let autoCheckPollTimer = null;
let _autoCheckSessionId = null;

function updateDnsAutoIndicator(text, cls) {
    const el = document.getElementById('dnsAutoStatus');
    if (!el) return;
    el.textContent = text;
    el.className = 'status ' + (cls || '');
}

function startAutoCheckPolling(sid) {
    stopAutoCheckPolling();
    _autoCheckSessionId = sid;
    if (!sid) return;

    const tick = async () => {
        if (_autoCheckSessionId !== sid) return; // session changed
        try {
            const res = await fetch('/api/check_status', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sid})
            });
            if (!res.ok) return;
            const data = await res.json();
            if (!data.success) return;

            const status = data.status || 'unknown';
            const attempts = data.attempts || 0;
            const max = data.max_attempts || DNS_AUTO_CONFIG.max_attempts;
            const intervalSec = Math.round((data.interval_ms || DNS_AUTO_CONFIG.interval_ms) / 1000);

            const toggle = document.getElementById('dnsAutoToggle');
            if (toggle) toggle.checked = (status === 'pending');

            if (status === 'pending') {
                updateDnsAutoIndicator(
                    `Server auto-check: attempt ${attempts}/${max} (every ${intervalSec}s)`,
                    'orange'
                );
                if (data.last_message) {
                    setStatus('dnsStatus', data.last_message, 'orange');
                }
            } else if (status === 'verified') {
                updateDnsAutoIndicator(
                    `Auto-check: verified after ${attempts} attempt(s)`, 'green');
                setStatus('dnsStatus',
                    'All records found! You can now issue the certificate.', 'green');
                const issueBtn = document.getElementById('btnIssue');
                if (issueBtn) issueBtn.disabled = false;
                stopAutoCheckPolling();
            } else if (status === 'failed') {
                updateDnsAutoIndicator(
                    `Auto-check: failed — ${data.last_message || 'max attempts'}`,
                    'red');
                setStatus('dnsStatus',
                    data.last_message || 'Max attempts reached', 'red');
                stopAutoCheckPolling();
            } else if (status === 'stopped') {
                updateDnsAutoIndicator('Auto-check: stopped', 'orange');
                stopAutoCheckPolling();
            } else if (status === 'expired') {
                updateDnsAutoIndicator('Auto-check: session expired', 'red');
                setStatus('dnsStatus',
                    'Session is too old. Please create a new request.', 'red');
                stopAutoCheckPolling();
            } else {
                updateDnsAutoIndicator('Auto-check: ' + status, 'orange');
            }
        } catch (e) {
            console.warn('[autocheck] poll failed:', e);
        }
    };

    tick(); // immediate first tick
    autoCheckPollTimer = setInterval(tick, 3000);
}

function stopAutoCheckPolling() {
    if (autoCheckPollTimer) {
        clearInterval(autoCheckPollTimer);
        autoCheckPollTimer = null;
    }
    _autoCheckSessionId = null;
}

function onDnsAutoToggle(checkbox) {
    if (!sessionId) {
        checkbox.checked = false;
        return;
    }
    const enabled = checkbox.checked;

    fetch('/api/check_auto_toggle', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({session_id: sessionId, enabled})
    }).then(r => r.json()).then(data => {
        if (!data.success) {
            checkbox.checked = !enabled;
            showNotification(data.error || 'Toggle failed', 'error');
            return;
        }
        if (enabled) {
            startAutoCheckPolling(sessionId);
        } else {
            updateDnsAutoIndicator('Auto-check: stopped', 'orange');
            stopAutoCheckPolling();
        }
    }).catch(e => {
        checkbox.checked = !enabled;
        showNotification('Toggle failed: ' + e.message, 'error');
    });
}

/* ============ Issue: sessions list ============ */
async function loadSavedSessions() {
    const wrap = document.getElementById('sessionsList');
    const step = document.getElementById('stepResume');
    if (!wrap || !step) return;
    try {
        const res = await fetch('/api/sessions');
        const data = await res.json();
        if (!data.success || !data.sessions || data.sessions.length === 0) {
            step.style.display = 'none';
            return;
        }

        step.style.display = 'block';
        let html = '<p class="step-desc">Sessions marked “metadata only” cannot be resumed ' +
            'because the ACME client state was lost. Create a new request instead.</p>';
        html += '<table><thead><tr>' +
            '<th>Created</th><th>Domains</th><th>Status</th><th>Resumable</th><th></th>' +
            '</tr></thead><tbody>';

        data.sessions.forEach(s => {
            const created = s.created_at ? fmtDate(s.created_at) : '?';
            const dom = (s.domains || []).join(', ');
            const status = s.status || 'pending';
            const resumable = s.has_client
                ? '<span class="tag-ok">yes</span>'
                : '<span class="tag-warn">metadata only</span>';
            const sid = escapeHtml(s.session_id);
            html += `<tr>
                <td>${escapeHtml(created)}</td>
                <td>${escapeHtml(dom)}</td>
                <td>${escapeHtml(status)}</td>
                <td>${resumable}</td>
                <td style="white-space:nowrap;">
                    <button type="button" class="small" onclick="restoreSession('${sid}')">Resume</button>
                    <button type="button" class="small" onclick="shareSession('${sid}')">Share</button>
                    <button type="button" class="small" onclick="deleteSavedSession('${sid}')">Delete</button>
                </td>
            </tr>`;
        });
        html += '</tbody></table>';
        wrap.innerHTML = html;
    } catch (e) {
        step.style.display = 'none';
        console.warn('loadSavedSessions failed:', e);
    }
}

function shareSession(id) {
    const url = new URL(location.href);
    url.searchParams.set('session', id);
    url.hash = 'issue';
    const link = url.toString();
    navigator.clipboard.writeText(link).then(() => {
        showNotification('Link copied: ' + link, 'success');
    }).catch(() => {
        prompt('Copy this link:', link);
    });
}

async function restoreSession(id) {
    setStatus('dnsStatus', 'Restoring session...', 'orange');
    try {
        const res = await fetch('/api/sessions/' + encodeURIComponent(id));
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Session not found');

        sessionId = data.session_id;
        rememberSession(sessionId);
        _setUrlSession(sessionId);

        if (data.domains && data.domains.length) {
            const d = document.getElementById('domains');
            if (d) d.value = data.domains.join(', ');
        }

        const tbody = document.querySelector('#tokensTable tbody');
        if (tbody) {
            tbody.innerHTML = '';
            const tokens = data.tokens || {};
            let n = 0;
            const rows = [];
            if (Array.isArray(tokens)) {
                tokens.forEach(t => {
                    if (!t || !t.fqdn || !t.value) return;
                    rows.push([t.fqdn, t.value]);
                    n += 1;
                });
            } else if (tokens && typeof tokens === 'object') {
                Object.keys(tokens).forEach(fqdn => {
                    const raw = tokens[fqdn];
                    const vals = Array.isArray(raw) ? raw : (raw ? [raw] : []);
                    vals.forEach(val => {
                        if (val == null) return;
                        rows.push([fqdn, String(val)]);
                        n += 1;
                    });
                });
            }
            rows.forEach(([fqdn, val]) => {
                tbody.innerHTML += `<tr>
                    <td class="copyable" data-value="${escapeHtml(fqdn)}">
                        <span>${escapeHtml(fqdn)}</span>
                        <button type="button" class="copy-btn" title="Copy" aria-label="Copy" onclick="copyCell(this)">
                            ${ICON_COPY}
                        </button>
                    </td>
                    <td class="copyable" data-value="${escapeHtml(val)}">
                        <span>${escapeHtml(val)}</span>
                        <button type="button" class="copy-btn" title="Copy" aria-label="Copy" onclick="copyCell(this)">
                            ${ICON_COPY}
                        </button>
                    </td>
                </tr>`;
            });
        }

        document.getElementById('step2').style.display = 'block';
        document.getElementById('step3').style.display = 'block';

        const checkBtn = document.getElementById('btnCheck');
        const issueBtn = document.getElementById('btnIssue');

        if (data.has_client) {
            if (checkBtn) checkBtn.disabled = false;
            if (issueBtn) issueBtn.disabled = true;
            setStatus('dnsStatus',
                'Session restored. Click "Check DNS" or wait for server auto-check.',
                'green');
            startAutoCheckPolling(sessionId);
        } else {
            if (checkBtn) checkBtn.disabled = true;
            if (issueBtn) issueBtn.disabled = true;
            setStatus('dnsStatus',
                'Session metadata was restored, but the ACME client could not be ' +
                'recovered (server restart). Please create a new request.',
                'red');
            stopAutoCheckPolling();
            updateDnsAutoIndicator('Auto-check: client unavailable', 'red');
        }

        log('Restored session ' + sessionId);
        setTimeout(() => {
            const step2 = document.getElementById('step2');
            if (step2) step2.scrollIntoView({behavior: 'smooth', block: 'start'});
        }, 100);

        loadSavedSessions();
    } catch (e) {
        console.error('[restoreSession]', e);
        setStatus('dnsStatus', 'Restore failed: ' + e.message, 'red');
        log('Restore failed: ' + e.message);
    }
}

async function deleteSavedSession(id) {
    if (!confirm('Delete this saved request?')) return;
    try {
        await fetch('/api/sessions/' + encodeURIComponent(id), {method: 'DELETE'});
        if (sessionId === id) {
            sessionId = null;
            rememberSession(null);
            _setUrlSession(null);
            stopAutoCheckPolling();
        }
        loadSavedSessions();
    } catch (e) {
        console.warn('deleteSavedSession failed:', e);
    }
}

async function createRequest() {
    const domains = document.getElementById('domains').value;
    const btn = document.getElementById('btnCreate');
    btn.disabled = true;
    setStatus('dnsStatus', 'Creating request...', 'orange');

    try {
        const res = await fetch('/api/create', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domains})
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        sessionId = data.session_id;
        rememberSession(sessionId);
        _setUrlSession(sessionId);

        const tbody = document.querySelector('#tokensTable tbody');
        tbody.innerHTML = '';
        data.tokens.forEach(t => {
            tbody.innerHTML += `<tr>
                <td class="copyable" data-value="${escapeHtml(t.fqdn)}">
                    <span>${escapeHtml(t.fqdn)}</span>
                    <button type="button" class="copy-btn" title="Copy" aria-label="Copy" onclick="copyCell(this)">
                        ${ICON_COPY}
                    </button>
                </td>
                <td class="copyable" data-value="${escapeHtml(t.value)}">
                    <span>${escapeHtml(t.value)}</span>
                    <button type="button" class="copy-btn" title="Copy" aria-label="Copy" onclick="copyCell(this)">
                        ${ICON_COPY}
                    </button>
                </td>
            </tr>`;
        });

        document.getElementById('step2').style.display = 'block';
        document.getElementById('step3').style.display = 'block';

        const checkBtn = document.getElementById('btnCheck');
        if (checkBtn) checkBtn.disabled = false;
        document.getElementById('btnIssue').disabled = true;

        setStatus('dnsStatus', 'Records received. Add them to DNS.', 'orange');
        log('Tokens received. Add the TXT records and click "Check DNS".');
        log('Server auto-check started in the background.');

        setTimeout(() => {
            const step2 = document.getElementById('step2');
            if (step2) step2.scrollIntoView({behavior: 'smooth', block: 'start'});
        }, 100);

        loadSavedSessions();
        startAutoCheckPolling(sessionId);
    } catch (e) {
        setStatus('dnsStatus', 'Error: ' + e.message, 'red');
        log('Error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

async function checkDNS() {
    const btn = document.getElementById('btnCheck');
    if (!btn) return;
    btn.disabled = true;
    setStatus('dnsStatus', 'Checking DNS...', 'orange');
    log('DNS check started...');

    try {
        const res = await fetch('/api/check', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId})
        });
        const data = await res.json();
        if (data.success) {
            setStatus('dnsStatus',
                'All records found! You can now issue the certificate.', 'green');
            document.getElementById('btnIssue').disabled = false;
            log('DNS records successfully propagated.');
            stopAutoCheckPolling();
            btn.disabled = false;
        } else {
            setStatus('dnsStatus', data.message || 'Check failed', 'red');
            log('Check failed: ' + (data.message || 'unknown error'));
            if (data.message && /not found|not restored|expired/i.test(data.message)) {
                document.getElementById('btnIssue').disabled = true;
                btn.disabled = true;
                return;
            }
            btn.disabled = false;
        }
    } catch (e) {
        setStatus('dnsStatus', 'Error: ' + e.message, 'red');
        log('Check error: ' + e.message);
        btn.disabled = false;
    }
}

async function issueCert() {
    const btn = document.getElementById('btnIssue');
    btn.disabled = true;
    setStatus('issueStatus', 'Requesting certificate...', 'orange');

    try {
        const res = await fetch('/api/issue', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId})
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Unknown error');

        document.getElementById('outCert').value = data.certificate;
        document.getElementById('outChain').value = data.chain;
        document.getElementById('outKey').value = data.private_key;
        document.getElementById('result').style.display = 'block';

        setStatus('issueStatus', 'Done! Copy the three parts into your panel.', 'green');
        log('Certificate issued.');
        stopAutoCheckPolling();
        rememberSession(null);
        _setUrlSession(null);
        sessionId = null;
        loadSavedSessions();
    } catch (e) {
        setStatus('issueStatus', 'Error: ' + e.message, 'red');
        log('Issue error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}
