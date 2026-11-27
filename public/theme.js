// Runs in <head> before first paint so there is no flash of the wrong theme.
// Uses the saved choice if there is one, otherwise the system preference.
(function () {
    var theme = null;
    try { theme = localStorage.getItem('theme'); } catch (e) { /* storage blocked */ }
    if (theme !== 'light' && theme !== 'dark') {
        theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', theme);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'light' ? '#fdf8f0' : '#111c26');
})();
