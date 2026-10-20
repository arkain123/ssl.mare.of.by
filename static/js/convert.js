/* ============ Convert ============ */
const PKCS12_TARGETS = ['pkcs12', 'pkcs12-p12', 'pkcs12-b64', 'pfx', 'pfx-b64'];

let convFileB64 = null;

function _el(id) { return document.getElementById(id); }

function _friendlyName() {
    const el = _el('outFriendlyName');
    return el ? el.value.trim() : '';
}

function _resetFriendlyName() {
    const el = _el('outFriendlyName');
    if (el) el.value = '';
}

function _resetPasswords() {
    const p1 = _el('outConvPass');
    const p2 = _el('outConvPassConfirm');
    if (p1) p1.value = '';
    if (p2) p2.value = '';
}

(function wireConvertInputs() {
    const fileEl = document.getElementById('convFile');
    const textEl = document.getElementById('convText');
    if (!fileEl || !textEl) return;

    fileEl.addEventListener('change', e => {
        const f = e.target.files[0];
        if (!f) {
            convFileB64 = null;
            document.getElementById('convFileName').textContent = '';
            return;
        }
        convFileB64 = null;
        fileToBase64(f).then(b64 => { convFileB64 = b64; });
        document.getElementById('convFileName').textContent = `${f.name} (${f.size} bytes)`;
        textEl.value = '';
    });

    textEl.addEventListener('input', e => {
        if (e.target.value.trim()) {
            fileEl.value = '';
            document.getElementById('convFileName').textContent = '';
            convFileB64 = null;
        }
    });

    document.querySelectorAll('input[name="outFormat"]').forEach(r => {
        r.addEventListener('change', () => {
            const isPkcs12 = PKCS12_TARGETS.includes(r.value);
            const box = _el('outPassWrap');
            if (box) box.style.display = isPkcs12 ? 'block' : 'none';

            if (!isPkcs12) {
                _resetPasswords();
                _resetFriendlyName();
            }

            document.querySelectorAll('.format-grid label').forEach(l => {
                const inp = l.querySelector('input');
                l.classList.toggle('selected', inp && inp.checked);
            });
        });
    });
})();

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
    _resetPasswords();
    _resetFriendlyName();
    document.getElementById('step-detected').style.display = 'none';
    document.getElementById('step-output').style.display = 'none';
    document.getElementById('step-result').style.display = 'none';
    const box = _el('outPassWrap');
    if (box) box.style.display = 'none';
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
    const p1 = _el('outConvPass');
    const p2 = _el('outConvPassConfirm');
    payload.output_password = p1 ? p1.value : '';
    payload.output_password_confirm = p2 ? p2.value : '';
    payload.friendly_name = _friendlyName();

    if (!payload.target) {
        setStatus('convertStatus', 'Select an output format', 'red');
        return;
    }

    const isPkcs12 = PKCS12_TARGETS.includes(payload.target);
    if (isPkcs12) {
        if (!payload.output_password) {
            setStatus('convertStatus', 'PKCS#12 requires an output password', 'red');
            return;
        }
        if (payload.output_password !== payload.output_password_confirm) {
            setStatus('convertStatus', 'Output passwords do not match', 'red');
            return;
        }
    } else {
        payload.output_password = '';
        payload.output_password_confirm = '';
        payload.friendly_name = '';
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
    if (!sel) return;
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
            const hint = document.getElementById('gsHint');
            if (hint) hint.textContent = item ? (item.description || '') : '';
        });

        gsCatalogLoaded = true;
    } catch (e) {
        sel.innerHTML = '<option value="">Failed to load list</option>';
        const hint = document.getElementById('gsHint');
        if (hint) hint.textContent = 'Error: ' + e.message;
    }
}

function injectGsIntermediate() {
    const sel = document.getElementById('gsSelect');
    if (!sel) return;
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
    const existing = chainEl.value.trim();
    const pem = item.pem.trim();

    if (existing.includes(pem)) {
        setStatus('verifyStatus', 'This intermediate is already in the chain', 'orange');
        return;
    }

    chainEl.value = existing ? existing + '\n\n' + pem + '\n' : pem + '\n';
    setStatus('verifyStatus',
        'Appended ' + item.label + ' to the end of the chain', 'green');
}

function clearGsIntermediate() {
    document.getElementById('vChain').value = '';
    document.getElementById('gsSelect').value = '';
    const hint = document.getElementById('gsHint');
    if (hint) hint.textContent = '';
    setStatus('verifyStatus', '', '');
}
