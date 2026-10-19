(function gw2PageProbe() {
    'use strict';
    // 唯讀偵察：記錄商城類網頁的結構與文字樣本，用來評估網頁介面繁體化。
    // 不修改頁面、不讀取輸入框內容、不讀 cookie、不記錄網址的查詢字串與請求內容。
    // 結果寫進 localStorage（key = gw2probe.v1.<host>），只存在本機的遊戲快取資料夾。
    try {
        var host = String(location.hostname || '');
        if (!/^(tradingpost|gemstore|vault|exchange)-[a-z0-9-]+\.ncplatform\.net$/i.test(host)) return;
        if (window.__gw2PageProbe) return;
        window.__gw2PageProbe = true;

        var KEY = 'gw2probe.v1.' + host;
        var MAX_JSON = 160000;
        var run = { v: 1, host: host, t0: Date.now(), href: '', navLang: '', navLangs: '', snaps: [], net: [], mut: null, err: [] };
        var saveTimer = 0;

        function safeUrl(u) {
            try { return String(u).split('#')[0].split('?')[0].slice(0, 200); } catch (e) { return ''; }
        }

        function save() {
            try {
                var s = JSON.stringify(run);
                if (s.length > MAX_JSON) {
                    run.net = run.net.slice(-60);
                    run.snaps = run.snaps.slice(-3);
                    s = JSON.stringify(run);
                }
                localStorage.setItem(KEY, s);
            } catch (e) { }
        }

        function saveSoon() {
            if (saveTimer) return;
            saveTimer = setTimeout(function () { saveTimer = 0; save(); }, 3000);
        }

        function note(what) {
            try { if (run.err.length < 30) run.err.push(String(what).slice(0, 160)); } catch (e) { }
        }

        function frameworks() {
            var f = {};
            f.mithril = typeof window.m;
            try { f.mithrilVer = window.m && window.m.version ? String(window.m.version) : ''; } catch (e) { }
            f.react = typeof window.React;
            f.reactRoot = !!document.querySelector('[data-reactroot]');
            f.preact = typeof window.preact;
            f.vue = typeof window.Vue;
            f.angular = typeof window.angular;
            f.jquery = typeof window.jQuery;
            f.yui = typeof window.YUI;
            f.gw2 = typeof window.GW2;
            try { if (window.GW2) f.gw2Keys = Object.keys(window.GW2).slice(0, 30); } catch (e) { }
            try { if (window.GW2 && window.GW2.config && window.GW2.config.features) f.gw2Features = Object.keys(window.GW2.config.features).length; } catch (e) { }
            return f;
        }

        function collectText(s) {
            var seen = {}, list = [], total = 0, cjk = 0, ascii = 0;
            if (!document.body) return;
            var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
            var n;
            while ((n = w.nextNode())) {
                var p = n.parentNode;
                var tag = p && p.nodeName ? p.nodeName : '';
                if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') continue;
                var t = String(n.nodeValue || '').replace(/\s+/g, ' ').replace(/^ | $/g, '');
                if (!t) continue;
                total++;
                if (/[㐀-鿿]/.test(t)) cjk++; else ascii++;
                if (t.length > 80) t = t.slice(0, 80);
                if (!seen[t] && list.length < 300) { seen[t] = 1; list.push(tag + '|' + t); }
            }
            s.textTotal = total;
            s.textCjk = cjk;
            s.textAscii = ascii;
            s.texts = list;
        }

        function attrSamples() {
            var out = [];
            var nodes = document.querySelectorAll('[placeholder],[title],[aria-label],[alt]');
            for (var i = 0; i < nodes.length && out.length < 60; i++) {
                var el = nodes[i];
                var names = ['placeholder', 'title', 'aria-label', 'alt'];
                for (var j = 0; j < names.length; j++) {
                    var v = el.getAttribute(names[j]);
                    if (v) out.push(el.nodeName + '|' + names[j] + '|' + String(v).slice(0, 60));
                }
            }
            return out.slice(0, 60);
        }

        function inputs() {
            var out = [];
            var nodes = document.querySelectorAll('input,textarea,select');
            for (var i = 0; i < nodes.length && i < 40; i++) {
                var el = nodes[i];
                out.push({ tag: el.nodeName, type: el.type || '', name: el.name || '', id: el.id || '', ph: String(el.getAttribute('placeholder') || '').slice(0, 60), ml: el.maxLength });
            }
            return out;
        }

        function outline() {
            var out = [];
            if (!document.body) return out;
            var queue = [{ el: document.body, d: 0 }];
            while (queue.length && out.length < 150) {
                var item = queue.shift();
                var el = item.el;
                var label = el.nodeName.toLowerCase();
                if (el.id) label += '#' + String(el.id).slice(0, 30);
                var cls = String(el.className && el.className.baseVal === undefined ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 2);
                if (cls.length) label += '.' + cls.join('.');
                out.push(item.d + '|' + label + '|' + el.children.length);
                if (item.d < 3) {
                    for (var i = 0; i < el.children.length && i < 12; i++) queue.push({ el: el.children[i], d: item.d + 1 });
                }
            }
            return out;
        }

        function scripts() {
            var out = [];
            var list = document.scripts || [];
            var inline = 0;
            for (var i = 0; i < list.length; i++) {
                if (list[i].src) { if (out.length < 30) out.push(safeUrl(list[i].src)); } else inline++;
            }
            return { src: out, inline: inline };
        }

        function lsKeys() {
            var out = [];
            for (var i = 0; i < localStorage.length && out.length < 40; i++) {
                var k = localStorage.key(i);
                if (k && k.indexOf('gw2probe.') !== 0) out.push(String(k).slice(0, 60));
            }
            return out;
        }

        function nativeKeys() {
            try { return window.native ? Object.keys(window.native).slice(0, 40) : []; } catch (e) { return []; }
        }

        function snap(label) {
            var s = { label: label, t: Date.now() - run.t0 };
            try { s.ready = document.readyState; } catch (e) { }
            try { s.title = String(document.title || '').slice(0, 80); } catch (e) { }
            try { s.lang = String(document.documentElement.getAttribute('lang') || ''); } catch (e) { }
            try { s.href = safeUrl(location.href); } catch (e) { }
            try { s.fw = frameworks(); } catch (e) { note('fw:' + e); }
            try { collectText(s); } catch (e) { note('text:' + e); }
            try { s.attrs = attrSamples(); } catch (e) { note('attrs:' + e); }
            try { s.inputs = inputs(); } catch (e) { note('inputs:' + e); }
            try { s.outline = outline(); } catch (e) { note('outline:' + e); }
            try { s.scripts = scripts(); } catch (e) { note('scripts:' + e); }
            try { s.ls = lsKeys(); } catch (e) { note('ls:' + e); }
            try { s.native = nativeKeys(); } catch (e) { note('native:' + e); }
            try { s.font = String(getComputedStyle(document.body).fontFamily || '').slice(0, 120); } catch (e) { }
            run.snaps.push(s);
            if (run.snaps.length > 4) run.snaps.shift();
            save();
        }

        function net(kind, url, status, type, ms) {
            try {
                if (run.net.length >= 200) return;
                run.net.push({ k: kind, u: url, s: status, c: String(type || '').slice(0, 40), ms: ms });
                saveSoon();
            } catch (e) { }
        }

        function hookNet() {
            try {
                if (typeof window.fetch === 'function') {
                    var origFetch = window.fetch;
                    window.fetch = function (input) {
                        var t = Date.now();
                        var url = '';
                        try { url = safeUrl(typeof input === 'string' ? input : (input && input.url) || ''); } catch (e) { }
                        var p = origFetch.apply(this, arguments);
                        try {
                            p.then(function (r) {
                                var ct = '';
                                try { ct = r && r.headers && r.headers.get ? r.headers.get('content-type') : ''; } catch (e) { }
                                net('fetch', url, r ? r.status : 0, ct, Date.now() - t);
                            }, function () { net('fetch', url, 0, '', Date.now() - t); });
                        } catch (e) { }
                        return p;
                    };
                }
            } catch (e) { note('fetch:' + e); }
            try {
                var proto = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
                if (proto && proto.open && proto.send) {
                    var origOpen = proto.open, origSend = proto.send;
                    proto.open = function (method, url) {
                        try { this.__gw2p = { m: String(method || ''), u: safeUrl(url) }; } catch (e) { }
                        return origOpen.apply(this, arguments);
                    };
                    proto.send = function () {
                        var self = this, t = Date.now();
                        try {
                            self.addEventListener('loadend', function () {
                                var ct = '';
                                try { ct = self.getResponseHeader('content-type'); } catch (e) { }
                                net('xhr', self.__gw2p ? self.__gw2p.m + ' ' + self.__gw2p.u : '', self.status, ct, Date.now() - t);
                            });
                        } catch (e) { }
                        return origSend.apply(this, arguments);
                    };
                }
            } catch (e) { note('xhr:' + e); }
        }

        function observe() {
            try {
                var mut = { batches: 0, records: 0, maxBatch: 0, textChanges: 0 };
                run.mut = mut;
                var mo = new MutationObserver(function (list) {
                    mut.batches++;
                    mut.records += list.length;
                    if (list.length > mut.maxBatch) mut.maxBatch = list.length;
                    for (var i = 0; i < list.length; i++) if (list[i].type === 'characterData') mut.textChanges++;
                });
                mo.observe(document, { childList: true, subtree: true, characterData: true });
            } catch (e) { note('mo:' + e); }
        }

        try { run.href = safeUrl(location.href); } catch (e) { }
        try { run.navLang = String(navigator.language || ''); run.navLangs = String((navigator.languages || []).join(',')); } catch (e) { }

        hookNet();
        observe();
        save();

        var times = [2000, 6000, 15000, 40000, 90000];
        for (var i = 0; i < times.length; i++) {
            (function (ms) { setTimeout(function () { snap('t+' + (ms / 1000) + 's'); }, ms); })(times[i]);
        }
        try { window.addEventListener('load', function () { snap('load'); }); } catch (e) { }
    } catch (e) {
        try { localStorage.setItem('gw2probe.v1.error', String(e).slice(0, 200)); } catch (e2) { }
    }
})();
