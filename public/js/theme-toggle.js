// Theme toggle script with icon update - auto-injects button
(function () {
    const THEME_KEY = 'theme';
    const html = document.documentElement;

    // Get saved theme or default to light
    const savedTheme = localStorage.getItem(THEME_KEY) || 'light';
    html.setAttribute('data-theme', savedTheme);

    // Create and inject the toggle button when DOM is ready
    document.addEventListener('DOMContentLoaded', function () {
        injectToggleButton();
        updateIcon(savedTheme);
    });

    function injectToggleButton() {
        // Find the navbar collapse div
        const navbarCollapse = document.querySelector('.navbar-collapse');
        if (navbarCollapse) {
            // Check if button already exists
            if (!document.getElementById('theme-toggle-btn')) {
                const btn = document.createElement('button');
                btn.id = 'theme-toggle-btn';
                btn.className = 'btn btn-sm btn-outline-secondary ml-2';
                btn.onclick = toggleTheme;
                btn.title = 'Alternar Tema';
                btn.innerHTML = '<i id="theme-icon" class="fas fa-moon"></i>';
                navbarCollapse.appendChild(btn);
            }
        }
    }

    function toggleTheme() {
        const current = html.getAttribute('data-theme');
        const next = current === 'light' ? 'dark' : 'light';
        html.setAttribute('data-theme', next);
        localStorage.setItem(THEME_KEY, next);
        updateIcon(next);
    }

    function updateIcon(theme) {
        const icon = document.getElementById('theme-icon');
        if (icon) {
            if (theme === 'dark') {
                icon.className = 'fas fa-sun text-warning';
            } else {
                icon.className = 'fas fa-moon';
            }
        }
    }

    // Expose toggle function globally
    window.toggleTheme = toggleTheme;
})();
