/* OptPress JWT – Admin JS */
(function () {
    'use strict';
console.log('OptPress JWT Admin JS loaded');
    /* ── Tab Navigation ──────────────────────────────── */
    function initTabs() {
        var btns = document.querySelectorAll('.opjwt-tab-btn');
        var panels = document.querySelectorAll('.opjwt-tab-panel');

        btns.forEach(function (btn) {
            btn.addEventListener('click', function () {
                var target = btn.getAttribute('data-tab');

                btns.forEach(function (b) { b.classList.remove('active'); });
                panels.forEach(function (p) { p.classList.remove('active'); });

                btn.classList.add('active');
                var panel = document.getElementById('opjwt-tab-' + target);
                if (panel) panel.classList.add('active');

                /* Persist selected tab across page reloads */
                try { sessionStorage.setItem('opjwt_active_tab', target); } catch (e) {}
            });
        });

        /* Restore last active tab */
        try {
            var saved = sessionStorage.getItem('opjwt_active_tab');
            if (saved) {
                var savedBtn = document.querySelector('.opjwt-tab-btn[data-tab="' + saved + '"]');
                if (savedBtn) { savedBtn.click(); return; }
            }
        } catch (e) {}

        /* Default: activate first tab */
        if (btns.length > 0) btns[0].click();
    }

    /* ── Copy-to-clipboard for endpoint code blocks ──── */
    function initCopyButtons() {
        document.querySelectorAll('.opjwt-copy-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var target = document.getElementById(btn.getAttribute('data-target'));
                if (!target) return;
                var text = target.innerText || target.textContent;
                navigator.clipboard.writeText(text).then(function () {
                    var orig = btn.innerText;
                    btn.innerText = '✓ Copied!';
                    setTimeout(function () { btn.innerText = orig; }, 1500);
                }).catch(function () {});
            });
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        initTabs();
        initCopyButtons();
    });
}());
