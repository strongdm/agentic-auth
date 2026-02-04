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

    // Initialize DNS lookup buttons
    initDNSLookup();
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

/**
 * Initialize DNS lookup buttons on profile pages
 */
function initDNSLookup() {
    document.querySelectorAll('.dns-lookup-btn').forEach(button => {
        button.addEventListener('click', async function(e) {
            e.preventDefault();
            const domain = this.dataset.domain;
            const subject = this.dataset.subject;
            const resultDiv = this.parentElement.querySelector('.dns-result');

            if (!resultDiv) return;

            // Show loading state
            this.disabled = true;
            this.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="12"/></svg> Checking...';
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = '<span class="dns-loading">Looking up DNS records...</span>';

            try {
                const response = await fetch(`/api/v1/dns-lookup?domain=${encodeURIComponent(domain)}&subject=${encodeURIComponent(subject)}`);
                const data = await response.json();

                if (data.found) {
                    const statusClass = data.verified ? 'dns-verified' : 'dns-found';
                    const statusText = data.verified ? 'Verified' : 'Found (not verified)';
                    resultDiv.innerHTML = `
                        <div class="${statusClass}">
                            <strong>TXT Record:</strong> ${data.record}<br>
                            <strong>Value:</strong> <code>${data.value}</code><br>
                            <strong>Status:</strong> <span class="badge badge-${data.verified ? 'verified' : 'pending'}">${statusText}</span>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="dns-not-found">
                            <strong>No TXT record found</strong><br>
                            Expected record: <code>${data.record}</code>
                        </div>
                    `;
                }
            } catch (err) {
                resultDiv.innerHTML = `<div class="dns-error">Error looking up DNS: ${err.message}</div>`;
            }

            // Reset button
            this.disabled = false;
            this.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: -2px;"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Check DNS';
        });
    });
}
