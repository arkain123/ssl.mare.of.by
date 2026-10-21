/* ============ Icons (inline SVG, no external font) ============ */
const ICON_COPY = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
const ICON_CHECK = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>';

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

/* ============ Generic helpers ============ */
function log(msg) {
    const el = document.getElementById('log');
    if (!el) return;
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
    if (!el) return;
    el.textContent = text;
    el.className = 'status ' + (cls || '');
}

function copyField(id) {
    const el = document.getElementById(id);
    if (!el) return;
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

function showNotification(message, type) {
    const n = document.createElement('div');
    n.style.cssText = `
        position: fixed; top: 20px; right: 20px; padding: 12px 18px;
        background: ${type === 'error' ? 'var(--bad-bg)' : 'var(--ok-bg)'};
        color: ${type === 'error' ? 'var(--bad)' : 'var(--ok)'};
        border: 1px solid currentColor; border-radius: 8px; z-index: 10000;
        font-size: 13px; font-weight: 600; max-width: 360px;
    `;
    n.textContent = message;
    document.body.appendChild(n);
    setTimeout(() => n.remove(), 3000);
}

function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try {
            document.execCommand('copy') ? resolve() : reject(new Error('execCommand failed'));
        } catch (e) {
            reject(e);
        } finally {
            document.body.removeChild(ta);
        }
    });
}

function copyCell(el) {
    const btn = el && el.tagName === 'BUTTON' ? el : null;
    const cell = btn ? el.closest('td') : el;
    if (!cell) return;

    const rawText = cell.dataset.value != null
        ? cell.dataset.value
        : cell.textContent.trim();

    copyText(rawText).then(() => {
        if (btn) {
            const original = btn.innerHTML;
            btn.classList.add('copied');
            btn.innerHTML = ICON_CHECK;
            setTimeout(() => {
                btn.innerHTML = original;
                btn.classList.remove('copied');
            }, 1200);
        } else {
            cell.classList.add('copied');
            setTimeout(() => cell.classList.remove('copied'), 800);
        }
    }).catch(e => {
        showNotification('Copy failed: ' + e.message, 'error');
    });
}

function _setUrlSession(id) {
    try {
        const url = new URL(location.href);
        if (id) url.searchParams.set('session', id);
        else url.searchParams.delete('session');
        history.replaceState(null, '', url.toString());
    } catch (e) {}
}
