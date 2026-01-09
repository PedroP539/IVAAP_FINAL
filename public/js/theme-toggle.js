// Theme toggle script
(function () {
    const THEME_KEY = 'theme';
    const html = document.documentElement;
    const savedTheme = localStorage.getItem(THEME_KEY) || 'light';
    html.setAttribute('data-theme', savedTheme);

    function toggleTheme() {
        const current = html.getAttribute('data-theme');
        const next = current === 'light' ? 'dark' : 'light';
        html.setAttribute('data-theme', next);
        localStorage.setItem(THEME_KEY, next);
    }

    // Expose toggle function globally for button onclick
    window.toggleTheme = toggleTheme;
})();
