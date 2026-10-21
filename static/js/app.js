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
    if (typeof stopAutoCheckPolling === 'function') stopAutoCheckPolling();
});
window.addEventListener('pagehide', () => {
    if (typeof stopAutoCheckPolling === 'function') stopAutoCheckPolling();
});

// Pause polling when the tab is hidden; resume when it comes back
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        if (typeof stopAutoCheckPolling === 'function') stopAutoCheckPolling();
    } else if (typeof sessionId !== 'undefined' && sessionId
            && typeof startAutoCheckPolling === 'function') {
        startAutoCheckPolling(sessionId);
    }
});
