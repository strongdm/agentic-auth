// AgentKey - Client-side JavaScript

// Theme definitions
const themes = {
    'sdm-brand': { label: 'SDM Brand', accent: '#22a6b8', isDefault: true },
    'original': { label: 'Original', accent: '#a855f7' },
    'ember': { label: 'Ember', accent: '#f59e0b' },
    'terminal': { label: 'Terminal', accent: '#06b6d4' },
    'forest': { label: 'Forest', accent: '#10b981' },
    'coral': { label: 'Coral', accent: '#f43f5e' },
    'obsidian': { label: 'Obsidian', accent: '#fafafa' }
};

const THEME_STORAGE_KEY = 'agentkey-theme';

document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme
    initTheme();

    // Initialize theme selector
    initThemeSelector();

    // Initialize copy buttons
    initCopyButtons();
});

/**
 * Initialize theme from localStorage or default
 */
function initTheme() {
    const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    const theme = savedTheme && themes[savedTheme] ? savedTheme : 'sdm-brand';
    applyTheme(theme);
}

/**
 * Apply a theme to the document
 */
function applyTheme(themeName) {
    document.documentElement.setAttribute('data-theme', themeName);
    localStorage.setItem(THEME_STORAGE_KEY, themeName);

    // Update active state in dropdown if it exists
    document.querySelectorAll('.theme-option').forEach(option => {
        option.classList.toggle('active', option.dataset.theme === themeName);
    });
}

/**
 * Initialize the theme selector dropdown
 */
function initThemeSelector() {
    const selector = document.querySelector('.theme-selector');
    if (!selector) return;

    const toggle = selector.querySelector('.theme-toggle');
    const dropdown = selector.querySelector('.theme-dropdown');

    if (!toggle || !dropdown) return;

    // Toggle dropdown
    toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('hidden');
        toggle.setAttribute('aria-expanded', !dropdown.classList.contains('hidden'));
    });

    // Handle theme selection
    dropdown.querySelectorAll('.theme-option').forEach(option => {
        option.addEventListener('click', () => {
            const theme = option.dataset.theme;
            applyTheme(theme);
            dropdown.classList.add('hidden');
            toggle.setAttribute('aria-expanded', 'false');

            // Update toggle label
            const label = toggle.querySelector('.theme-label');
            if (label) {
                label.textContent = themes[theme].label;
            }
        });
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
        if (!selector.contains(e.target)) {
            dropdown.classList.add('hidden');
            toggle.setAttribute('aria-expanded', 'false');
        }
    });

    // Close on Escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            dropdown.classList.add('hidden');
            toggle.setAttribute('aria-expanded', 'false');
        }
    });

    // Set initial active state
    const currentTheme = localStorage.getItem(THEME_STORAGE_KEY) || 'sdm-brand';
    dropdown.querySelectorAll('.theme-option').forEach(option => {
        option.classList.toggle('active', option.dataset.theme === currentTheme);
    });
}

/**
 * Initialize all copy-to-clipboard buttons
 */
function initCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', async function(e) {
            e.preventDefault();
            const textToCopy = this.dataset.copy;

            try {
                await navigator.clipboard.writeText(textToCopy);
                showCopyFeedback(this, 'Copied!');
            } catch (err) {
                // Fallback for older browsers
                fallbackCopy(textToCopy);
                showCopyFeedback(this, 'Copied!');
            }
        });
    });
}

/**
 * Show temporary feedback on copy button
 */
function showCopyFeedback(button, message) {
    const originalText = button.textContent;
    button.textContent = message;
    button.classList.add('copied');

    setTimeout(() => {
        button.textContent = originalText;
        button.classList.remove('copied');
    }, 1500);
}

/**
 * Fallback copy method for browsers without clipboard API
 */
function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
}

/**
 * Format a fingerprint for display (add colons if not present)
 */
function formatFingerprint(fingerprint) {
    if (fingerprint.includes(':')) {
        return fingerprint;
    }
    // Add colons every 2 characters
    return fingerprint.match(/.{1,2}/g).join(':');
}

/**
 * Debounce function for search inputs
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
