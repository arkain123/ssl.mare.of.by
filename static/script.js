/* ============ Theme ============ */
const THEME_KEY = 'ssl_tools_theme';
const systemDark = window.matchMedia('(prefers-color-scheme: dark)');

function getThemePref() {
    try { return localStorage.getItem(THEME_KEY) || 'auto'; }
    catch (e) { return 'auto'; }
}

function applyResolvedTheme() {
    const pref = getThemePref();
    const resolved = pref === 'auto'
        ? (systemDark.matches ? 'dark' : 'light')
        : pref;
    document.documentElement.setAttribute('data-theme', resolved);
    updateThemeButton(pref);
}

function updateThemeButton(pref) {
    const btn = document.getElementById('themeToggle');
    if (!btn) return;
    const icons = { auto: '🌓', light: '☀', dark: '🌙' };
    btn.textContent = icons[pref] || icons.auto;
    btn.title = 'Theme: ' + pref + ' (click to cycle)';
    btn.setAttribute('aria-label', 'Theme: ' + pref);
}

function cycleTheme() {
    const order = ['auto', 'light', 'dark'];
    const next = order[(order.indexOf(getThemePref()) + 1) % order.length];
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    applyResolvedTheme();
}

systemDark.addEventListener('change', () => {
    if (getThemePref() === 'auto') applyResolvedTheme();
});

applyResolvedTheme();

/* ============ Tabs ============ */
function activateTab(name) {
    document.querySelectorAll('.tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === name);
    });
    document.querySelectorAll('.tab-content').forEach(c => {
        c.classList.toggle('active', c.id === 'tab-' + name);
    });
}

document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', e => {
        e.preventDefault();
        const name = t.dataset.tab;
        history.replaceState(null, '', '#' + name);
        activateTab(name);
    });
});

(function initTab() {
    const h = (location.hash || '').replace('#', '');
    activateTab(['verify', 'live', 'convert'].includes(h) ? h : 'issue');
})();

/* ============ Helpers ============ */
function log(msg) {
    const el = document.getElementById('log');
    el.innerHTML += msg + '<br>';
    el.scrollTop = el.scrollHeight;
}

function convLog(msg) {
    const el = document.getElementById('convLog');
    if (!el) return;
    el.innerHTML += msg + '<br>';
    el.scrollTop = el.scrollHeight;
}

function setStatus(id, text, cls) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = 'status ' + (cls || '');
}

function copyField(id) {
    const el = document.getElementById(id);
    el.select();
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
}

function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

function fmtDate(iso) {
    try { return new Date(iso).toLocaleString(); }
    catch { return iso; }
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function b64ToBlob(b64, mime) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Blob([bytes], {type: mime});
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const idx = reader.result.indexOf(',');
            resolve(reader.result.slice(idx + 1));
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

/* ============ Issue ============ */
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

async function loadSavedSessions() {
    const wrap = document.getElementById('sessionsList');
    const step = document.getElementById('stepResume');
    try {
        const res = await fetch('/api/sessions');
        const data = await res.json();
        if (!data.success || !data.sessions || data.sessions.length === 0) {
            step.style.display = 'none';
            return;
        }

        step.style.display = 'block';
        let html = '<table><thead><tr>' +
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

async function restoreSession(id) {
    setStatus('dnsStatus', 'Restoring session...', 'orange');
    try {
        const res = await fetch('/api/sessions/' + encodeURIComponent(id));
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Session not found');

        sessionId = data.session_id;
        rememberSession(sessionId);

        if (data.domains && data.domains.length) {
            document.getElementById('domains').value = data.domains.join(', ');
        }

        const tbody = document.querySelector('#tokensTable tbody');
        tbody.innerHTML = '';
        const tokens = data.tokens || {};
        let n = 0;
        Object.keys(tokens).forEach(fqdn => {
            (tokens[fqdn] || []).forEach(val => {
                tbody.innerHTML += `<tr><td>${escapeHtml(fqdn)}</td><td>${escapeHtml(val)}</td></tr>`;
                n += 1;
            });
        });

        document.getElementById('step2').style.display = 'block';
        document.getElementById('step3').style.display = 'block';

        const issueBtn = document.getElementById('btnIssue');
        if (data.has_client) {
            issueBtn.disabled = true;
            setStatus('dnsStatus',
                'Session restored (' + n + ' TXT record(s)). Click "Check DNS" to continue.',
                'green');
        } else {
            issueBtn.disabled = true;
            setStatus('dnsStatus',
                'Session restored, but the ACME client could not be recovered. ' +
                'Please create a new request.',
                'orange');
        }

        log('Restored session ' + sessionId + ' with ' + n + ' token(s).');
        loadSavedSessions();
    } catch (e) {
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
        }
        loadSavedSessions();
    } catch (e) {
        console.warn('deleteSavedSession failed:', e);
    }
}

(function autoRestore() {
    const saved = readRememberedSession();
    const h = (location.hash || '').replace('#', '');
    if (saved && (h === '' || h === 'issue')) {
        restoreSession(saved).catch(() => {
            rememberSession(null);
        });
    }
    loadSavedSessions();
})();

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
        const tbody = document.querySelector('#tokensTable tbody');
        tbody.innerHTML = '';
        data.tokens.forEach(t => {
            tbody.innerHTML += `<tr><td>${escapeHtml(t.fqdn)}</td><td>${escapeHtml(t.value)}</td></tr>`;
        });

        document.getElementById('step2').style.display = 'block';
        document.getElementById('step3').style.display = 'block';
        setStatus('dnsStatus', 'Records received. Add them to DNS.', 'orange');
        log('Tokens received. Add the TXT records and click "Check DNS".');
        loadSavedSessions();
    } catch (e) {
        setStatus('dnsStatus', 'Error: ' + e.message, 'red');
        log('Error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

async function checkDNS() {
    const btn = document.getElementById('btnCheck');
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
            setStatus('dnsStatus', 'All records found! You can now issue the certificate.', 'green');
            document.getElementById('btnIssue').disabled = false;
            log('DNS records successfully propagated.');
        } else {
            setStatus('dnsStatus', data.message, 'red');
            log('Check failed: ' + data.message);
            btn.disabled = false;
        }
    } catch (e) {
        setStatus('dnsStatus', 'Error: ' + e.message, 'red');
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
        rememberSession(null);
        sessionId = null;
        loadSavedSessions();
    } catch (e) {
        setStatus('issueStatus', 'Error: ' + e.message, 'red');
        log('Issue error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

/* ============ Verify ============ */
function clearVerify() {
    document.getElementById('vCert').value = '';
    document.getElementById('vChain').value = '';
    document.getElementById('vKey').value = '';
    document.getElementById('verifyResult').style.display = 'none';
    setStatus('verifyStatus', '', '');
}

async function runVerify() {
    const cert = document.getElementById('vCert').value;
    const chain = document.getElementById('vChain').value;
    const key = document.getElementById('vKey').value;
    const btn = document.getElementById('btnVerify');
    btn.disabled = true;
    setStatus('verifyStatus', 'Verifying...', 'orange');

    try {
        const res = await fetch('/api/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({certificate: cert, chain: chain, private_key: key})
        });
        const data = await res.json();
        renderVerifyResult(data);

        if (data.success) {
            setStatus('verifyStatus', 'OK', 'green');
        } else {
            setStatus('verifyStatus', 'Issues detected', 'red');
        }
    } catch (e) {
        setStatus('verifyStatus', 'Error: ' + e.message, 'red');
    } finally {
        btn.disabled = false;
    }
}

async function runLiveCheck() {
    const host = document.getElementById('liveHost').value.trim();
    const btn = document.getElementById('btnLive');
    if (!host) {
        setStatus('liveStatus', 'Enter a hostname', 'red');
        return;
    }
    btn.disabled = true;
    setStatus('liveStatus', 'Connecting...', 'orange');

    try {
        const res = await fetch('/api/check_live', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({hostname: host})
        });
        const data = await res.json();
        renderVerifyResult(data, 'liveResult');

        if (data.success) {
            setStatus('liveStatus', 'OK', 'green');
        } else {
            setStatus('liveStatus', 'Issues detected', 'red');
        }
    } catch (e) {
        setStatus('liveStatus', 'Error: ' + e.message, 'red');
    } finally {
        btn.disabled = false;
    }
}

function renderVerifyResult(data, targetId) {
    const el = document.getElementById(targetId || 'verifyResult');
    const c = data.certificate;
    const chain = data.chain || {};

    let html = '';

    /* Chain visualization */
    html += '<div class="step"><h2>Chain</h2>';
    html += '<div class="chain-viz">';

    if (c) {
        const leafOk = !c.expired && !c.not_yet_valid;
        html += chainNode('Leaf', c.subject_cn, leafOk ? 'ok' : 'bad');
    }

    const links = chain.links || [];

    if (links.length > 0) {
        links.forEach((link, i) => {
            html += `<div class="chain-arrow ${link.verified ? 'ok' : 'bad'}">→</div>`;
            const isLast = i === links.length - 1;
            const node = (chain.nodes || [])[i + 1];
            const label = node ? node.label : (isLast ? 'Root' : 'Intermediate');
            const name  = node ? node.name : link.to;
            const ok    = link.verified;
            const cls   = (label === 'Root' ? 'root ' : '') + (ok ? 'ok' : 'bad');
            html += chainNode(label, name, cls);
        });
    } else {
        html += '<div class="chain-arrow none">-&gt;</div>';
        html += chainNode('Intermediate', 'not provided', 'unknown', true);
    }

    html += '</div></div>';

    /* Errors / warnings */
    if ((data.errors && data.errors.length) || (data.warnings && data.warnings.length)) {
        html += '<div class="step"><h2>Issues</h2><ul class="err-list">';
        (data.errors || []).forEach(e => {
            html += `<li class="err">${escapeHtml(e)}</li>`;
        });
        (data.warnings || []).forEach(w => {
            html += `<li class="warn">${escapeHtml(w)}</li>`;
        });
        html += '</ul></div>';
    }

    /* Connection */
    if (data.connection) {
        const cc = data.connection;
        html += '<div class="step verify-details"><h2>Connection</h2><table>';
        html += row('Host', cc.hostname + ':' + cc.port);
        html += row('TLS version', cc.tls_version || '—');
        if (cc.cipher) {
            html += row('Cipher', `${cc.cipher.name} (${cc.cipher.bits} bits, ${cc.cipher.protocol})`);
        }
        html += rowHtml('Trusted by system CA',
            cc.verify_ok
                ? '<span class="tag-ok">yes</span>'
                : '<span class="tag-bad">no</span>');
        if (!cc.verify_ok && cc.verify_error) {
            html += rowHtml('Verification error',
                `<span class="tag-bad">${escapeHtml(cc.verify_error)}</span>`);
        }
        html += '</table></div>';
    }

    /* Details */
    html += '<div class="step verify-details"><h2>Details</h2>';

    if (c) {
        html += '<h3>Certificate</h3><table>';
        html += row('Subject', c.subject);
        html += row('Issuer', c.issuer);
        html += row('Valid from', fmtDate(c.not_before));
        html += row('Valid until', fmtDate(c.not_after));
        const daysCls = c.expired ? 'tag-bad' : (c.days_left < 14 ? 'tag-warn' : 'tag-ok');
        html += rowHtml('Days left',
            `<span class="${daysCls}">${c.days_left}</span>`);
        html += row('Serial', c.serial);
        html += row('Signature algorithm', c.signature_algorithm);
        html += row('Is CA', c.is_ca ? 'yes' : 'no');
        html += '</table>';

        html += '<h3>Domains covered</h3><ul>';
        if (c.domains && c.domains.length) {
            c.domains.forEach(d => html += `<li>${escapeHtml(d)}</li>`);
        } else {
            html += '<li class="muted">none</li>';
        }
        html += '</ul>';
    }

    if (data.key) {
        html += '<h3>Private key</h3><table>';
        if (data.key.type) html += row('Type', data.key.type);
        if ('matches_certificate' in data.key) {
            html += rowHtml('Matches certificate',
                data.key.matches_certificate
                    ? '<span class="tag-ok">yes</span>'
                    : '<span class="tag-bad">no</span>');
        }
        if (data.key.error) {
            html += rowHtml('Error', `<span class="tag-bad">${escapeHtml(data.key.error)}</span>`);
        }
        html += '</table>';
    }

    if (chain && chain.length !== undefined) {
        html += '<h3>Chain</h3><table>';
        html += row('Certificates in chain', chain.length);
        html += rowHtml('Valid',
            chain.valid
                ? '<span class="tag-ok">yes</span>'
                : '<span class="tag-bad">no</span>');
        html += rowHtml('Ends with self-signed root',
            chain.complete
                ? '<span class="tag-ok">yes</span>'
                : '<span class="tag-warn">no (cross-signed - normal for LE)</span>');
        html += '</table>';

        if (chain.certificates && chain.certificates.length) {
            html += '<h3>Chain contents</h3><table>';
            html += '<thead><tr><th>#</th><th>Subject</th><th>Issuer</th></tr></thead><tbody>';
            chain.certificates.forEach((cc, i) => {
                html += `<tr>
                    <td>${i + 1}</td>
                    <td>${escapeHtml(cc.subject)}</td>
                    <td>${escapeHtml(cc.issuer)}</td>
                </tr>`;
            });
            html += '</tbody></table>';
        }
    }

    html += '</div>';

    el.innerHTML = html;
    el.style.display = 'block';
}

function row(label, value) {
    return rowHtml(label, escapeHtml(value));
}

function rowHtml(label, htmlValue) {
    return `<tr><td>${escapeHtml(label)}</td><td>${htmlValue}</td></tr>`;
}

function chainNode(label, name, cls, unknown) {
    const classes = 'chain-node ' + (cls || '') + (unknown ? ' unknown' : '');
    const nameHtml = name ? `<div class="chain-node-name">${escapeHtml(name)}</div>` : '';
    return `<div class="${classes}">
        <div class="chain-node-label">${escapeHtml(label)}</div>
        ${nameHtml}
    </div>`;
}

/* ============ Convert ============ */
let convFileB64 = null;

document.getElementById('convFile').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) {
        convFileB64 = null;
        document.getElementById('convFileName').textContent = '';
        return;
    }
    convFileB64 = null;
    fileToBase64(f).then(b64 => { convFileB64 = b64; });
    document.getElementById('convFileName').textContent = `${f.name} (${f.size} bytes)`;
    document.getElementById('convText').value = '';
});

document.getElementById('convText').addEventListener('input', e => {
    if (e.target.value.trim()) {
        document.getElementById('convFile').value = '';
        document.getElementById('convFileName').textContent = '';
        convFileB64 = null;
    }
});

document.querySelectorAll('input[name="outFormat"]').forEach(r => {
    r.addEventListener('change', () => {
        const isPfx = r.value === 'pfx';
        document.getElementById('outPassWrap').style.display = isPfx ? 'block' : 'none';
        document.querySelectorAll('.format-grid label').forEach(l => {
            const inp = l.querySelector('input');
            l.classList.toggle('selected', inp && inp.checked);
        });
    });
});

function buildConvertPayload() {
    const text = document.getElementById('convText').value;
    const password = document.getElementById('convPass').value;
    const payload = {password};
    if (convFileB64) {
        payload.input_b64 = convFileB64;
    } else if (text.trim()) {
        payload.input_text = text;
    } else {
        throw new Error('Provide a file or paste content');
    }
    return payload;
}

function clearConvert() {
    document.getElementById('convFile').value = '';
    document.getElementById('convFileName').textContent = '';
    document.getElementById('convText').value = '';
    document.getElementById('convPass').value = '';
    document.getElementById('outConvPass').value = '';
    document.getElementById('outConvPassConfirm').value = '';
    document.getElementById('step-detected').style.display = 'none';
    document.getElementById('step-output').style.display = 'none';
    document.getElementById('step-result').style.display = 'none';
    document.getElementById('outPassWrap').style.display = 'none';
    setStatus('inspectStatus', '', '');
    setStatus('convertStatus', '', '');
    convFileB64 = null;
}

async function runInspect() {
    let payload;
    try { payload = buildConvertPayload(); }
    catch (e) { setStatus('inspectStatus', e.message, 'red'); return; }

    const btn = document.getElementById('btnInspect');
    btn.disabled = true;
    setStatus('inspectStatus', 'Inspecting...', 'orange');
    convLog('Inspecting input...');

    try {
        const res = await fetch('/api/convert/inspect', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Inspection failed');

        renderInspect(data);
        setStatus('inspectStatus', 'Detected: ' + data.source_format, 'green');
        convLog('Source format: ' + data.source_format);
        document.getElementById('step-detected').style.display = 'block';
        document.getElementById('step-output').style.display = 'block';
        document.getElementById('step-result').style.display = 'none';
    } catch (e) {
        setStatus('inspectStatus', 'Error: ' + e.message, 'red');
        convLog('Error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

function renderInspect(data) {
    let html = '<table>';
    html += `<tr><td>Source format</td><td><b>${escapeHtml(data.source_format)}</b></td></tr>`;
    html += `<tr><td>Private key</td><td>${data.has_private_key
        ? '<span class="tag-ok">yes</span> (' + escapeHtml(data.key_type || '') + ')'
        : '<span class="tag-warn">no</span>'}</td></tr>`;
    html += `<tr><td>Certificate</td><td>${data.has_certificate
        ? '<span class="tag-ok">yes</span>'
        : '<span class="tag-warn">no</span>'}</td></tr>`;

    if (data.certificate) {
        html += `<tr><td>&nbsp;&nbsp;Subject</td><td>${escapeHtml(data.certificate.subject_cn)}</td></tr>`;
        html += `<tr><td>&nbsp;&nbsp;Issuer</td><td>${escapeHtml(data.certificate.issuer_cn)}</td></tr>`;
        html += `<tr><td>&nbsp;&nbsp;Valid until</td><td>${escapeHtml(data.certificate.not_after)}</td></tr>`;
    }

    html += `<tr><td>Chain</td><td>${data.chain_length} cert(s)</td></tr>`;
    if (data.chain && data.chain.length) {
        data.chain.forEach((c, i) => {
            html += `<tr><td>&nbsp;&nbsp;#${i + 1}</td><td>${escapeHtml(c.subject_cn)} &larr; issued by ${escapeHtml(c.issuer_cn)}</td></tr>`;
        });
    }

    html += `<tr><td>CSR</td><td>${data.has_csr ? 'yes' : 'no'}</td></tr>`;
    html += `<tr><td>Public key</td><td>${data.has_public_key ? 'yes' : 'no'}</td></tr>`;
    html += '</table>';

    if (data.warnings && data.warnings.length) {
        html += '<ul class="err-list" style="margin-top:12px;">';
        data.warnings.forEach(w => {
            html += `<li class="warn">${escapeHtml(w)}</li>`;
        });
        html += '</ul>';
    }

    document.getElementById('detectedContent').innerHTML = html;
}

async function runConvert() {
    let payload;
    try { payload = buildConvertPayload(); }
    catch (e) { setStatus('convertStatus', e.message, 'red'); return; }

    payload.target = (document.querySelector('input[name="outFormat"]:checked') || {}).value;
    payload.output_password = document.getElementById('outConvPass').value;
    payload.output_password_confirm = document.getElementById('outConvPassConfirm').value;

    if (!payload.target) {
        setStatus('convertStatus', 'Select an output format', 'red');
        return;
    }

    const btn = document.getElementById('btnConvert');
    btn.disabled = true;
    setStatus('convertStatus', 'Converting...', 'orange');
    convLog('Target format: ' + payload.target);

    try {
        const res = await fetch('/api/convert/output', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Conversion failed');

        renderFiles(data.files);
        setStatus('convertStatus', 'Done - ' + data.files.length + ' file(s)', 'green');
        convLog('Produced ' + data.files.length + ' file(s)');
        document.getElementById('step-result').style.display = 'block';
    } catch (e) {
        setStatus('convertStatus', 'Error: ' + e.message, 'red');
        convLog('Error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

let convOutputFiles = [];

function renderFiles(files) {
    convOutputFiles = files;
    let html = '';
    files.forEach((f, i) => {
        html += '<div style="margin-bottom:16px;">';
        html += `<label style="display:block;"><b>${escapeHtml(f.name)}</b> <span class="file-meta">(${f.size} bytes)</span> `;
        html += `<button type="button" class="small" onclick="downloadConvFile(${i})">download</button>`;
        if (f.text !== null && f.text !== undefined) {
            html += ` <button type="button" class="small" onclick="copyConvFile(${i})">copy</button>`;
        }
        html += '</label>';

        if (f.text !== null && f.text !== undefined && f.text.length < 65536) {
            html += `<textarea id="convFile_${i}" readonly rows="8">${escapeHtml(f.text)}</textarea>`;
        } else {
            html += '<div class="binary-notice">Binary file - use the download button</div>';
        }
        html += '</div>';
    });
    document.getElementById('convertFiles').innerHTML = html;
}

function downloadConvFile(idx) {
    const f = convOutputFiles[idx];
    if (!f) return;
    const blob = b64ToBlob(f.b64, 'application/octet-stream');
    downloadBlob(blob, f.name);
}

function copyConvFile(idx) {
    const el = document.getElementById('convFile_' + idx);
    if (!el) return;
    el.select();
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
}

/* ============ GlobalSign intermediate injector ============ */
let gsCatalogLoaded = false;
let gsCatalogById = {};

async function loadGsCatalog() {
    if (gsCatalogLoaded) return;
    const sel = document.getElementById('gsSelect');
    try {
        const res = await fetch('/api/globalsign-intermediates');
        const data = await res.json();
        if (!data.success) throw new Error(data.error || 'Failed to load');

        sel.innerHTML = '<option value="">- select an intermediate -</option>';
        gsCatalogById = {};

        data.groups.forEach(group => {
            const og = document.createElement('optgroup');
            og.label = group.name + ' (' + group.items.length + ')';
            group.items.forEach(item => {
                const opt = document.createElement('option');
                opt.value = item.id;
                opt.textContent = item.label + ' - ' + item.algorithm + ' - ' + item.year;
                opt.title = item.description || '';
                og.appendChild(opt);
                gsCatalogById[item.id] = item;
            });
            sel.appendChild(og);
        });

        sel.addEventListener('change', () => {
            const item = gsCatalogById[sel.value];
            document.getElementById('gsHint').textContent = item ? (item.description || '') : '';
        });

        gsCatalogLoaded = true;
    } catch (e) {
        sel.innerHTML = '<option value="">Failed to load list</option>';
        document.getElementById('gsHint').textContent = 'Error: ' + e.message;
    }
}

function injectGsIntermediate() {
    const sel = document.getElementById('gsSelect');
    const id = sel.value;
    if (!id) {
        setStatus('verifyStatus', 'Pick an intermediate from the list first', 'orange');
        return;
    }
    const item = gsCatalogById[id];
    if (!item || !item.pem) {
        setStatus('verifyStatus', 'Certificate payload missing', 'red');
        return;
    }

    const chainEl = document.getElementById('vChain');
    const hadContent = chainEl.value.trim().length > 0;
    chainEl.value = item.pem.trim() + '\n';

    setStatus('verifyStatus',
        (hadContent ? 'Replaced chain with ' : 'Inserted ') + item.label,
        'green');
}

function clearGsIntermediate() {
    document.getElementById('vChain').value = '';
    document.getElementById('gsSelect').value = '';
    document.getElementById('gsHint').textContent = '';
    setStatus('verifyStatus', '', '');
}

(function wireGsCatalog() {
    const verifyTab = document.querySelector('.tab[data-tab="verify"]');
    if (verifyTab) {
        verifyTab.addEventListener('click', loadGsCatalog);
    }
    const h = (location.hash || '').replace('#', '');
    if (h === 'verify') loadGsCatalog();
})();
