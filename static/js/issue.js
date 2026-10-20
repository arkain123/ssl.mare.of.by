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

/* ============ Issue: DNS auto-check ============ */
const DNS_AUTO_INTERVAL_MS = 30_000;
const DNS_AUTO_MAX_ATTEMPTS = 40;
const DNS_AUTO_START_DELAY_MS = 3_000;

let dnsAutoTimer = null;
let dnsAutoAttempts = 0;
let dnsAutoActive = false;

function dnsAutoStart() {
    dnsAutoStop();
    if (!sessionId) return;

    dnsAutoActive = true;
    dnsAutoAttempts = 0;

    const toggle = document.getElementById('dnsAutoToggle');
    if (toggle) toggle.checked = true;
    updateDnsAutoIndicator('Auto-check: waiting for first tick...', 'orange');

    log('DNS auto-check enabled (every ' + (DNS_AUTO_INTERVAL_MS / 1000) + 's)');
    dnsAutoScheduleNext(DNS_AUTO_START_DELAY_MS);
}

function dnsAutoStop(reason) {
    if (dnsAutoTimer) {
        clearTimeout(dnsAutoTimer);
        dnsAutoTimer = null;
    }
    const wasActive = dnsAutoActive;
    dnsAutoActive = false;

    const toggle = document.getElementById('dnsAutoToggle');
    if (toggle) toggle.checked = false;

    if (wasActive) {
        updateDnsAutoIndicator(
            reason ? 'Auto-check stopped: ' + reason : 'Auto-check off',
            'orange');
        if (reason) log('DNS auto-check stopped: ' + reason);
    }
}

function dnsAutoScheduleNext(delay) {
    if (dnsAutoTimer) clearTimeout(dnsAutoTimer);
    dnsAutoTimer = setTimeout(dnsAutoTick, delay);
}

async function dnsAutoTick() {
    if (!dnsAutoActive || !sessionId) return;

    dnsAutoAttempts += 1;

    if (dnsAutoAttempts > DNS_AUTO_MAX_ATTEMPTS) {
        dnsAutoStop('max attempts reached (' + DNS_AUTO_MAX_ATTEMPTS + ')');
        return;
    }

    updateDnsAutoIndicator(
        'Auto-check: attempt ' + dnsAutoAttempts + '/' + DNS_AUTO_MAX_ATTEMPTS + '...',
        'orange');

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
            const issueBtn = document.getElementById('btnIssue');
            if (issueBtn) issueBtn.disabled = false;
            log('DNS records successfully propagated (auto).');
            dnsAutoStop('success');
            return;
        }

        setStatus('dnsStatus', data.message || 'Waiting for DNS propagation...', 'orange');
        log('Auto-check #' + dnsAutoAttempts + ': ' + (data.message || 'not yet'));

        if (data.message && /not found|not restored|expired/i.test(data.message)) {
            dnsAutoStop('session lost');
            return;
        }

        dnsAutoScheduleNext(DNS_AUTO_INTERVAL_MS);
    } catch (e) {
        log('Auto-check error: ' + e.message);
        dnsAutoScheduleNext(DNS_AUTO_INTERVAL_MS);
    }
}

function updateDnsAutoIndicator(text, cls) {
    const el = document.getElementById('dnsAutoStatus');
    if (!el) return;
    el.textContent = text;
    el.className = 'status ' + (cls || '');
}

function onDnsAutoToggle(checkbox) {
    if (checkbox.checked) dnsAutoStart();
    else dnsAutoStop('toggled off by user');
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
                    <td class="copyable" title="Click to copy" onclick="copyCell(this)">${escapeHtml(fqdn)}</td>
                    <td class="copyable" title="Click to copy" onclick="copyCell(this)">${escapeHtml(val)}</td>
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
                'Session restored. Click "Check DNS" to continue.', 'green');
            dnsAutoStart();
        } else {
            if (checkBtn) checkBtn.disabled = true;
            if (issueBtn) issueBtn.disabled = true;
            setStatus('dnsStatus',
                'Session metadata was restored, but the ACME client could not be ' +
                'recovered (server restart). Please create a new request.',
                'red');
            dnsAutoStop();
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
            dnsAutoStop('session deleted');
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
                <td class="copyable" title="Click to copy" onclick="copyCell(this)">${escapeHtml(t.fqdn)}</td>
                <td class="copyable" title="Click to copy" onclick="copyCell(this)">${escapeHtml(t.value)}</td>
            </tr>`;
        });

        document.getElementById('step2').style.display = 'block';
        document.getElementById('step3').style.display = 'block';

        const checkBtn = document.getElementById('btnCheck');
        if (checkBtn) checkBtn.disabled = false;
        document.getElementById('btnIssue').disabled = true;

        setStatus('dnsStatus', 'Records received. Add them to DNS.', 'orange');
        log('Tokens received. Add the TXT records and click "Check DNS".');

        setTimeout(() => {
            const step2 = document.getElementById('step2');
            if (step2) step2.scrollIntoView({behavior: 'smooth', block: 'start'});
        }, 100);

        loadSavedSessions();
        dnsAutoStart();
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
            dnsAutoStop('manual check succeeded');
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
        dnsAutoStop('certificate issued');
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
