import Alpine from 'alpinejs';
import agentChat from './agent-chat';

window.Alpine = Alpine;
Alpine.data('agentChat', agentChat);
Alpine.start();

const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ----------------------------------------------------------------- theme */
// Dark is the design's home theme. The toggle flips between dark and light and remembers the choice
// (same storage key as the original dashboard); the first visit follows the system setting.
(function theme() {
    const button = document.getElementById('theme-toggle');
    if (!button) return;
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    const read = () => { try { return localStorage.getItem('aegis-theme') || 'dark'; } catch { return 'dark'; } };
    const current = () => document.documentElement.dataset.theme;
    const label = () => {
        const next = current() === 'dark' ? 'light' : 'dark';
        button.setAttribute('aria-label', `Switch to ${next} theme`);
        button.title = `Switch to ${next} theme`;
    };
    button.addEventListener('click', () => {
        const next = current() === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = next;
        try { localStorage.setItem('aegis-theme', next); } catch {}
        label();
        announce(`${next[0].toUpperCase()}${next.slice(1)} theme on`);
    });
    system.addEventListener('change', () => {
        if (read() === 'system') { document.documentElement.dataset.theme = system.matches ? 'dark' : 'light'; label(); }
    });
    label();
})();

/* -------------------------------------------------------- live announcer */
let live;
function announce(message) {
    if (!live) {
        live = document.createElement('div');
        live.className = 'sr-only';
        live.setAttribute('role', 'status');
        live.setAttribute('aria-live', 'polite');
        document.body.appendChild(live);
    }
    live.textContent = '';
    requestAnimationFrame(() => { live.textContent = message; });
}

/* ---------------------------------------------------------------- toasts */
const icons = { ok: 'i-check', bad: 'i-warn' };
function dismiss(toast) {
    if (!toast || toast.classList.contains('leaving')) return;
    toast.classList.add('leaving');
    setTimeout(() => toast.remove(), reduced ? 0 : 220);
}
function toast(message, kind = 'ok', { action, timeout = kind === 'ok' ? 5000 : 0 } = {}) {
    const host = document.getElementById('toasts');
    if (!host) return;
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.setAttribute('role', kind === 'bad' ? 'alert' : 'status');
    el.innerHTML = `<svg class="icon" aria-hidden="true"><use href="#${icons[kind] || icons.ok}"/></svg><span></span>`;
    el.querySelector('span').textContent = message;
    if (action) {
        const a = document.createElement('button');
        a.type = 'button'; a.className = 'text-button'; a.textContent = action.label;
        a.addEventListener('click', () => { dismiss(el); action.run(); });
        el.append(a);
    }
    el.insertAdjacentHTML('beforeend', '<button type="button" class="toast-close" aria-label="Dismiss"><svg class="icon" aria-hidden="true"><use href="#i-close"/></svg></button>');
    host.appendChild(el);
    if (timeout) setTimeout(() => dismiss(el), timeout);
}
document.addEventListener('click', (e) => {
    const close = e.target.closest('.toast-close');
    if (close) dismiss(close.closest('.toast'));
});
document.querySelectorAll('.toast[data-autodismiss]').forEach((t) => setTimeout(() => dismiss(t), Number(t.dataset.autodismiss)));

/* Shared helpers for other scripts (workspace.js, agent chat). */
window.aegis = {
    toast,
    announce,
    agent(state) {
        document.documentElement.dataset.agent = state;
        const label = document.getElementById('agent-status');
        if (label) label.textContent = state === 'busy' ? 'AGENT WORKING' : 'AGENT IDLE';
    },
    pending(button, on, text) {
        if (!button) return;
        button.classList.toggle('is-loading', on);
        button.toggleAttribute('aria-busy', on);
        if (on) { button.dataset.wasDisabled = button.disabled ? '1' : ''; button.setAttribute('aria-disabled', 'true'); }
        else { button.removeAttribute('aria-disabled'); }
        if (on && text) announce(text);
    },
    async flash(button, ok, label) {
        if (!button) return;
        button.classList.add(ok ? 'is-success' : 'is-error');
        const prev = button.dataset.label ?? button.textContent;
        if (label) { button.dataset.label = prev; button.textContent = label; }
        await new Promise((r) => setTimeout(r, ok ? 700 : 900));
        button.classList.remove('is-success', 'is-error');
        if (label) button.textContent = prev;
    },
};

/* ------------------------------------------- forms: inline validation + pending */
// Forms with data-validate get messages next to the field instead of the browser's bubble; any
// form with data-pending disables its submit button while the request runs, so a second click
// cannot send it twice. Entered values are never cleared by these helpers.
const messages = {
    required: (name) => `Enter your ${name}.`,
    email: () => 'Enter an email address like name@example.com.',
    min: (n) => `Use at least ${n} characters.`,
    match: () => 'The two passwords do not match.',
};
function fieldName(field) {
    const label = field.id ? document.querySelector(`label[for="${field.id}"]`) : null;
    return (label?.textContent || field.name || 'value').trim().toLowerCase().replace(/\s*\(.*\)/, '');
}
function problem(field) {
    if (field.disabled || field.type === 'hidden' || field.type === 'checkbox') return '';
    const value = field.value.trim();
    if (field.required && !value) return messages.required(fieldName(field));
    if (value && field.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return messages.email();
    if (value && field.minLength > 0 && value.length < field.minLength) return messages.min(field.minLength);
    if (field.dataset.matches) {
        const other = field.form.querySelector(`[name="${field.dataset.matches}"]`);
        if (other && value !== other.value) return messages.match();
    }
    return '';
}
function show(field, text) {
    let box = document.getElementById(`${field.id}-error`);
    if (!text) {
        if (box) box.hidden = true;
        field.removeAttribute('aria-invalid');
        return;
    }
    if (!box) {
        box = document.createElement('p');
        box.className = 'field-error';
        box.dataset.for = field.id;
        box.id = `${field.id}-error`;
        (field.closest('.password-wrap') || field).after(box);
    }
    box.hidden = false;
    box.textContent = text;
    field.setAttribute('aria-invalid', 'true');
    field.setAttribute('aria-describedby', box.id);
}
document.querySelectorAll('form[data-validate]').forEach((form) => {
    form.setAttribute('novalidate', '');
    const fields = () => [...form.querySelectorAll('input,select,textarea')].filter((f) => f.name && f.name !== '_token');
    fields().forEach((f) => {
        f.addEventListener('blur', (e) => {
            // Moving to the submit button: let the submit validate, so the error box cannot push the button away mid-click.
            if (e.relatedTarget && e.relatedTarget.matches('[type=submit]')) return;
            if (!f.value.trim() && !f.getAttribute('aria-invalid')) return;
            f.dataset.touched = '1'; show(f, problem(f));
        });
        f.addEventListener('input', () => { if (f.dataset.touched || f.getAttribute('aria-invalid')) show(f, problem(f)); });
    });
    form.addEventListener('submit', (e) => {
        const bad = fields().find((f) => problem(f));
        fields().forEach((f) => { f.dataset.touched = '1'; show(f, problem(f)); });
        if (bad) {
            e.preventDefault();
            e.stopImmediatePropagation();
            bad.focus();
            announce('Some fields need attention. ' + problem(bad));
            const button = form.querySelector('[type=submit]');
            if (button && !reduced) { button.classList.remove('is-error'); void button.offsetWidth; button.classList.add('is-error'); setTimeout(() => button.classList.remove('is-error'), 400); }
        }
    }, true);
});
document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form.matches('form[data-pending]') || e.defaultPrevented) return;
    const button = e.submitter || form.querySelector('[type=submit]');
    if (form.dataset.sent) { e.preventDefault(); return; }
    form.dataset.sent = '1';
    window.aegis.pending(button, true, form.dataset.pending || 'Working');
    // If the page is restored from the back/forward cache, make the form usable again.
});
window.addEventListener('pageshow', () => {
    document.querySelectorAll('form[data-sent]').forEach((f) => {
        delete f.dataset.sent;
        window.aegis.pending(f.querySelector('.is-loading'), false);
    });
});

/* show / hide password */
document.querySelectorAll('input[type=password][data-reveal-toggle]').forEach((input) => {
    const wrap = document.createElement('div');
    wrap.className = 'password-wrap';
    input.before(wrap);
    wrap.append(input);
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'reveal-btn'; b.textContent = 'Show';
    b.setAttribute('aria-controls', input.id); b.setAttribute('aria-label', 'Show password');
    b.addEventListener('click', () => {
        const hidden = input.type === 'password';
        input.type = hidden ? 'text' : 'password';
        b.textContent = hidden ? 'Hide' : 'Show';
        b.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
    });
    wrap.append(b);
});

/* ---------------------------------------------------------- scroll reveal */
// A few below-the-fold groups fade in once as they enter the viewport. Without JS or
// IntersectionObserver the groups simply stay visible.
const reveals = document.querySelectorAll('[data-reveal]');
if ('IntersectionObserver' in window && !reduced && reveals.length) {
    const io = new IntersectionObserver((entries) => {
        entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add('is-in'); io.unobserve(en.target); } });
    }, { rootMargin: '0px 0px -8% 0px' });
    reveals.forEach((el) => io.observe(el));
} else {
    reveals.forEach((el) => el.classList.add('is-in'));
}

/* Anchor buttons that should also move keyboard focus to a field (e.g. "Start a conversation"). */
document.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-focus]');
    if (!a) return;
    const target = document.querySelector(a.dataset.focus);
    if (!target) return;
    e.preventDefault();
    target.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'center' });
    setTimeout(() => target.focus({ preventScroll: true }), reduced ? 0 : 300);
});
