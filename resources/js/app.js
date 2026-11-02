import Alpine from 'alpinejs';
import agentChat from './agent-chat';

window.Alpine = Alpine;
Alpine.data('agentChat', agentChat);
Alpine.start();

// Appearance selector in the sidebar (same storage key as the original dashboard).
const themeSelect = document.getElementById('theme');
if (themeSelect) {
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    let choice = 'system';
    try { choice = localStorage.getItem('aegis-theme') || 'system'; } catch {}
    if (!['light', 'dark', 'system'].includes(choice)) choice = 'system';
    const apply = () => {
        document.documentElement.dataset.theme = choice === 'system' ? (system.matches ? 'dark' : 'light') : choice;
    };
    themeSelect.value = choice;
    themeSelect.addEventListener('change', () => {
        choice = themeSelect.value;
        try { localStorage.setItem('aegis-theme', choice); } catch {}
        apply();
    });
    system.addEventListener('change', apply);
    apply();
}
