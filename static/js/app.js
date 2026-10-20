/* ============ Bootstrap ============ */
(function initTab() {
    const h = (location.hash || '').replace('#', '');
    activateTab(['verify', 'live', 'convert'].includes(h) ? h : 'issue');
})();

(function autoRestore() {
    const urlSession = new URLSearchParams(location.search).get('session');
    if (urlSession) {
        restoreSession(urlSession).catch(() => {
            rememberSession(null);
        });
        loadSavedSessions();
        return;
    }

    const saved = readRememberedSession();
    const h = (location.hash || '').replace('#', '');
    if (saved && (h === '' || h === 'issue')) {
        restoreSession(saved).catch(() => {
            rememberSession(null);
        });
    }
    loadSavedSessions();
})();

(function wireGsCatalog() {
    const verifyTab = document.querySelector('.tab[data-tab="verify"]');
    if (verifyTab) {
        verifyTab.addEventListener('click', loadGsCatalog);
    }
    const h = (location.hash || '').replace('#', '');
    if (h === 'verify') loadGsCatalog();
})();

window.addEventListener('beforeunload', () => {
    if (typeof dnsAutoActive !== 'undefined' && dnsAutoActive) {
        dnsAutoStop('page unload');
    }
});
