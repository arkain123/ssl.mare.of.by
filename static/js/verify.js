/* ============ Verify ============ */
function clearVerify() {
    document.getElementById('vCert').value = '';
    document.getElementById('vChain').value = '';
    document.getElementById('vKey').value = '';
    document.getElementById('verifyResult').style.display = 'none';
    const chainResult = document.getElementById('chainResult');
    if (chainResult) chainResult.style.display = 'none';
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

        if (data.success) setStatus('verifyStatus', 'OK', 'green');
        else setStatus('verifyStatus', 'Issues detected', 'red');
    } catch (e) {
        setStatus('verifyStatus', 'Error: ' + e.message, 'red');
    } finally {
        btn.disabled = false;
    }
}

async function buildChain() {
    const cert = document.getElementById('vCert').value.trim();
    if (!cert) {
        setStatus('verifyStatus', 'Certificate is required', 'red');
        return;
    }

    const includeRootEl = document.getElementById('includeRoot');
    const includeRoot = !!(includeRootEl && includeRootEl.checked);

    const btn = document.getElementById('btnBuildChain');
    btn.disabled = true;
    setStatus('verifyStatus', 'Building chain...', 'orange');

    try {
        const res = await fetch('/api/build_chain', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                certificate: cert,
                include_root: includeRoot,
            })
        });
        const data = await res.json();
        renderChainResult(data);

        if (data.success) {
            const withRoot = data.root_included ? ' (with root)' : '';
            setStatus('verifyStatus',
                `Chain built: ${data.chain.length} certificate(s)${withRoot}`, 'green');
        } else {
            setStatus('verifyStatus', 'Chain built with warnings', 'orange');
        }
    } catch (e) {
        setStatus('verifyStatus', 'Error: ' + e.message, 'red');
    } finally {
        btn.disabled = false;
    }
}

function renderChainResult(data) {
    const wrap = document.getElementById('chainResult');
    const content = document.getElementById('chainResultContent');
    if (!wrap || !content) return;

    const chain = data.chain || [];
    const errors = data.errors || [];
    const warnings = data.warnings || [];

    let html = '';

    if (errors.length) {
        html += '<ul class="err-list">';
        errors.forEach(e => html += `<li class="err">${escapeHtml(e)}</li>`);
        html += '</ul>';
    }
    if (warnings.length) {
        html += '<ul class="err-list">';
        warnings.forEach(w => html += `<li class="warn">${escapeHtml(w)}</li>`);
        html += '</ul>';
    }

    if (data.found_root && !data.root_included && data.excluded_root) {
        const s = data.excluded_root.subject || '(unknown)';
        html += `<p class="hint">Self-signed root <b>${escapeHtml(s)}</b> was found `
             + `but not included. Enable "Include self-signed root" and rebuild to add it.</p>`;
    }

    if (!chain.length) {
        content.innerHTML = html + '<p class="muted">No chain could be built.</p>';
        wrap.style.display = 'block';
        return;
    }

    html += '<div class="chain-viz">';
    chain.forEach((item, i) => {
        if (i > 0) html += '<div class="chain-arrow ok">→</div>';
        const cls = item.self_signed ? 'root ' : '';
        html += chainNode(item.type, item.info.subject_cn, cls + 'ok');
    });
    html += '</div>';

    html += '<table><thead><tr>' +
        '<th>#</th><th>Type</th><th>Subject CN</th><th>Issuer CN</th>' +
        '<th>Self-signed</th><th>Valid until</th><th>Source</th>' +
        '</tr></thead><tbody>';

    chain.forEach((item, i) => {
        const info = item.info || {};
        const sourceLabel = item.source === 'aia' ? 'AIA download'
            : item.source === 'local_store' ? 'Local CA store'
            : item.source === 'input' ? 'Input'
            : item.source || '—';
        const selfSignedCell = item.self_signed
            ? '<span class="tag-ok">yes</span>'
            : '<span class="muted">no</span>';
        html += `<tr>
            <td>${i + 1}</td>
            <td>${escapeHtml(item.type)}</td>
            <td>${escapeHtml(info.subject_cn || '—')}</td>
            <td>${escapeHtml(info.issuer_cn || '—')}</td>
            <td>${selfSignedCell}</td>
            <td>${escapeHtml(fmtDate(info.not_after))}</td>
            <td>${escapeHtml(sourceLabel)}</td>
        </tr>`;
    });
    html += '</tbody></table>';

    html += `<button type="button" class="small" onclick="useBuiltChain()">Use as intermediate chain</button>`;

    content.innerHTML = html;
    wrap.style.display = 'block';

    window._lastBuiltChain = chain;
}

function useBuiltChain() {
    const chain = window._lastBuiltChain || [];
    if (!chain.length) return;

    const intermediates = chain
        .slice(1)
        .filter(item => item.type !== 'root')
        .map(item => item.pem.trim())
        .filter(Boolean);

    if (!intermediates.length) {
        setStatus('verifyStatus',
            'No intermediate certificates in built chain', 'orange');
        return;
    }

    const chainEl = document.getElementById('vChain');
    chainEl.value = intermediates.join('\n\n') + '\n';
    setStatus('verifyStatus',
        `Inserted ${intermediates.length} intermediate certificate(s)`, 'green');
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

        if (data.success) setStatus('liveStatus', 'OK', 'green');
        else setStatus('liveStatus', 'Issues detected', 'red');
    } catch (e) {
        setStatus('liveStatus', 'Error: ' + e.message, 'red');
    } finally {
        btn.disabled = false;
    }
}

/* Live-chain download helpers */
let _lastLiveChainPem = [];

function downloadLivePem(which) {
    const chain = _lastLiveChainPem || [];
    if (!chain.length) return;

    let content, filename;
    if (which === 'leaf') {
        content = chain[0];
        filename = 'server-certificate.pem';
    } else {
        content = chain.join('\n');
        filename = 'fullchain.pem';
    }
    const blob = new Blob([content], {type: 'application/x-pem-file'});
    downloadBlob(blob, filename);
}

function copyLivePem(which) {
    const chain = _lastLiveChainPem || [];
    if (!chain.length) return;
    const content = which === 'leaf' ? chain[0] : chain.join('\n');
    copyText(content)
        .then(() => showNotification('Copied to clipboard', 'success'))
        .catch(e => showNotification('Copy failed: ' + e, 'error'));
}

/* Download an "unused" certificate PEM if the backend provided it */
function downloadUnusedPem(index) {
    const chain = window._lastVerifyChain || {};
    const unused = chain.unused || [];
    const item = unused[index];
    if (!item || !item.pem) {
        showNotification('PEM not available for this certificate', 'error');
        return;
    }
    const filename = (item.subject || 'unused')
        .replace(/[^a-z0-9._-]/gi, '_')
        .toLowerCase() + '.pem';
    const blob = new Blob([item.pem], {type: 'application/x-pem-file'});
    downloadBlob(blob, filename);
}

function renderVerifyResult(data, targetId) {
    const el = document.getElementById(targetId || 'verifyResult');
    if (!el) return;

    if (data.chain_pem) _lastLiveChainPem = data.chain_pem;
    window._lastVerifyChain = data.chain || {};

    const c = data.certificate;
    const chain = data.chain || {};

    let html = '';

    /* ---- Main chain visualization ---- */
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

    html += '</div>';

    /* ---- Unused certificates (secondary row, dimmed) ---- */
    if (chain.unused && chain.unused.length) {
        html += '<div style="margin-top:16px; padding-top:12px; border-top:1px dashed var(--border);">';
        html += '<div style="font-size:12px; color:var(--muted); margin-bottom:8px;">';
        html += 'Not part of the main verification path (e.g. cross-signed variants):';
        html += '</div>';
        html += '<div class="chain-viz" style="opacity:0.65;">';
        chain.unused.forEach((u, i) => {
            if (i > 0) html += '<div class="chain-arrow none">·</div>';
            const cls = (u.self_signed ? 'root ' : '') + 'unknown';
            html += chainNode('Unused', u.subject || u.subject_cn || '—', cls);
        });
        html += '</div></div>';
    }

    html += '</div>';

    /* ---- Errors / warnings ---- */
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

    /* ---- Connection ---- */
    if (data.connection) {
        const cc = data.connection;
        html += '<div class="step verify-details"><h2>Connection</h2><table>';
        html += row('Host', cc.hostname + ':' + cc.port);
        html += row('TLS version', cc.tls_version || '—');
        if (cc.cipher) {
            html += row('Cipher', `${cc.cipher.name} (${cc.cipher.bits} bits, ${cc.cipher.protocol})`);
        }
        html += rowHtml('Trusted by system CA',
            cc.verify_ok ? '<span class="tag-ok">yes</span>'
                         : '<span class="tag-bad">no</span>');
        if (!cc.verify_ok && cc.verify_error) {
            html += rowHtml('Verification error',
                `<span class="tag-bad">${escapeHtml(cc.verify_error)}</span>`);
        }
        html += '</table>';

        if (_lastLiveChainPem && _lastLiveChainPem.length) {
            html += '<div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">';
            html += '<button type="button" class="small" onclick="downloadLivePem(\'leaf\')">Download leaf (PEM)</button>';
            if (_lastLiveChainPem.length > 1) {
                html += '<button type="button" class="small" onclick="downloadLivePem(\'chain\')">Download full chain (PEM)</button>';
            }
            html += '<button type="button" class="small" onclick="copyLivePem(\'leaf\')">Copy leaf</button>';
            if (_lastLiveChainPem.length > 1) {
                html += '<button type="button" class="small" onclick="copyLivePem(\'chain\')">Copy full chain</button>';
            }
            html += '</div>';
        }

        html += '</div>';
    }

    /* ---- Details ---- */
    html += '<div class="step verify-details"><h2>Details</h2>';

    if (c) {
        html += '<h3>Certificate</h3><table>';
        html += row('Subject', c.subject);
        html += row('Issuer', c.issuer);
        html += row('Valid from', fmtDate(c.not_before));
        html += row('Valid until', fmtDate(c.not_after));
        const warnDays = window.CERT_EXPIRY_WARN_DAYS || 14;
        const daysCls = c.expired
            ? 'tag-bad'
            : (c.days_left < warnDays ? 'tag-warn' : 'tag-ok');
        html += rowHtml('Days left', `<span class="${daysCls}">${c.days_left}</span>`);
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
            chain.valid ? '<span class="tag-ok">yes</span>'
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

        if (chain.unused && chain.unused.length) {
            html += '<h3>Unused certificates</h3>';
            html += '<p class="hint">Provided, but not part of the main verification path. '
                 + 'Usually cross-signed variants of the same intermediate.</p>';
            html += '<table>';
            html += '<thead><tr>'
                 + '<th>Subject</th>'
                 + '<th>Issuer</th>'
                 + '<th>Self-signed</th>'
                 + '<th></th>'
                 + '</tr></thead><tbody>';
            chain.unused.forEach((u, i) => {
                const selfSigned = u.self_signed
                    ? '<span class="tag-ok">yes</span>'
                    : '<span class="muted">no</span>';
                const dl = u.pem
                    ? `<button type="button" class="small" onclick="downloadUnusedPem(${i})">download</button>`
                    : '';
                html += `<tr style="opacity:0.75;">
                    <td>${escapeHtml(u.subject || u.subject_cn || '—')}</td>
                    <td>${escapeHtml(u.issuer || u.issuer_cn || '—')}</td>
                    <td>${selfSigned}</td>
                    <td>${dl}</td>
                </tr>`;
            });
            html += '</tbody></table>';
        }
    }

    html += '</div>';

    el.innerHTML = html;
    el.style.display = 'block';
}

function row(label, value) { return rowHtml(label, escapeHtml(value)); }
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
