'use strict';

(function () {
    const form = document.getElementById('loginForm');
    const errBox = document.getElementById('loginError');
    const btn = document.getElementById('loginBtn');
    const pw = document.getElementById('password');

    function safeNext(p) {
        return (p && p.startsWith('/') && !p.startsWith('//') && !p.includes('\\') && !p.startsWith('/login')) ? p : '';
    }

    function showError(msg) {
        errBox.textContent = msg;
        errBox.classList.remove('hidden');
    }

    document.getElementById('togglePw').addEventListener('click', () => {
        const show = pw.type === 'password';
        pw.type = show ? 'text' : 'password';
        document.querySelector('#togglePw i').className = `fa-solid ${show ? 'fa-eye-slash' : 'fa-eye'} text-sm`;
    });

    // Demo accounts (localhost only): fill the form and sign in with one click
    document.querySelectorAll('.demo-login').forEach(b => b.addEventListener('click', () => {
        document.getElementById('username').value = b.dataset.user;
        pw.value = b.dataset.pass;
        document.querySelectorAll('.demo-login').forEach(x => { x.disabled = true; });
        form.requestSubmit();
        setTimeout(() => document.querySelectorAll('.demo-login').forEach(x => { x.disabled = false; }), 1500);
    }));

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errBox.classList.add('hidden');
        const username = document.getElementById('username').value.trim();
        const password = pw.value;
        if (!username || !password) {
            showError('Enter your user ID and password.');
            return;
        }
        btn.disabled = true;
        try {
            const url = window.apiUrl ? window.apiUrl('/api/auth/login') : '/api/auth/login';
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showError(res.status === 429 ? 'Too many sign-in attempts. Wait a minute and try again.'
                    : (typeof data.detail === 'string' ? data.detail : 'Sign-in failed.'));
                pw.value = '';
                pw.focus();
                return;
            }
            const forced = data.redirect && data.redirect.startsWith('/account');
            const next = safeNext(document.getElementById('nextPath').value);
            window.location.href = forced ? data.redirect : (next || data.redirect || '/');
        } catch (err) {
            showError('Cannot reach the server. Check your connection and try again.');
        } finally {
            btn.disabled = false;
        }
    });

    document.getElementById('username').focus();
})();
