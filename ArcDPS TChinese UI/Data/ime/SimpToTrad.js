function gw2SimpToTrad(DICT, T2S_PAIRS) {
    'use strict';
    // 啟動紀錄：啟動與出錯時各寫一筆到 localStorage（key = gw2s2t.<kind>.<host>，只留最近 12 筆），
    // 用來區分「腳本沒被執行」與「執行到一半出錯」。內容只有網址（不含查詢字串）、時間與步驟。
    var step = 'start';
    function note(kind, extra) {
        try {
            var h = String(location.hostname || '');
            if (!/^(tradingpost|gemstore|vault|exchange)-[a-z0-9-]+\.ncplatform\.net$/i.test(h)) return;
            var key = 'gw2s2t.' + kind + '.' + h;
            var list = JSON.parse(localStorage.getItem(key) || '[]');
            if (!(list instanceof Array)) list = [];
            var rec = { t: Date.now(), href: String(location.href).split('?')[0].split('#')[0].slice(0, 120), top: window === window.top, ready: document.readyState, step: step };
            if (extra) rec.x = String(extra).slice(0, 200);
            list.push(rec);
            while (list.length > 12) list.shift();
            localStorage.setItem(key, JSON.stringify(list));
        } catch (e) { }
    }
    note('boot');
    // 商城類網頁（交易行、寶石商城、魔法庫、兌換所）簡體 → 繁體。
    //  * 顯示的文字：用與遊戲內相同的字典（含詞彙規則），並持續監看頁面變動。
    //  * 搜尋框：頁面讀到的值轉回簡體（伺服器與物品名稱都是簡體），畫面上顯示繁體。
    //    輸入框一律用「逐字、字數不變」的對應，游標與選取範圍因此不會錯位。
    // DICT = [{i: 簡體, o: 繁體}, ...]；T2S_PAIRS = 繁體字與簡體字成對相連的字串。
    try {
        var host = String(location.hostname || '');
        if (!/^(tradingpost|gemstore|vault|exchange)-[a-z0-9-]+\.ncplatform\.net$/i.test(host)) return;
        if (window.__gw2S2T) { note('dup'); return; }

        var api = window.__gw2S2T = { version: 1, converted: 0, attrs: 0, errors: 0, inputHook: false, last: '' };
        var HOOK_INPUTS = true;

        step = 'index';
        // ---- 字典索引：第一個字 → 規則（由長到短） ----
        var index = {};
        var charS2T = {};
        var i, k;
        for (i = 0; i < DICT.length; i++) {
            var rule = DICT[i];
            if (!rule || !rule.i || typeof rule.o !== 'string') continue;
            k = rule.i.charAt(0);
            (index[k] || (index[k] = [])).push(rule);
            if (rule.i.length === 1 && rule.o.length === 1) charS2T[rule.i] = rule.o;
        }
        for (k in index) {
            if (Object.prototype.hasOwnProperty.call(index, k)) {
                index[k].sort(function (a, b) { return b.i.length - a.i.length; });
            }
        }
        var charT2S = {};
        for (i = 0; i + 1 < T2S_PAIRS.length; i += 2) charT2S[T2S_PAIRS.charAt(i)] = T2S_PAIRS.charAt(i + 1);

        // ---- 轉換 ----
        function isHan(code) {
            return (code >= 0x4E00 && code <= 0x9FFF) || (code >= 0xD840 && code <= 0xD87F);
        }

        // 顯示用：詞彙優先（與遊戲內的簡轉繁相同的比對方式）
        function s2t(s) {
            if (!s) return s;
            var out = '', n = s.length, p = 0, changed = false;
            while (p < n) {
                var c = s.charAt(p);
                var rules = isHan(s.charCodeAt(p)) ? index[c] : null;
                var hit = null;
                if (rules) {
                    for (var j = 0; j < rules.length; j++) {
                        var r = rules[j];
                        if (s.substr(p, r.i.length) === r.i) { hit = r; break; }
                    }
                }
                if (hit) { out += hit.o; p += hit.i.length; changed = true; } else { out += c; p++; }
            }
            return changed ? out : s;
        }

        // 輸入框用：逐字、字數不變
        function s2tChars(s) {
            if (!s) return s;
            var out = '', changed = false;
            for (var p = 0; p < s.length; p++) {
                var c = s.charAt(p);
                var m = charS2T[c];
                if (m !== undefined) { out += m; changed = true; } else out += c;
            }
            return changed ? out : s;
        }

        function t2sChars(s) {
            if (!s) return s;
            var out = '', changed = false;
            for (var p = 0; p < s.length; p++) {
                var c = s.charAt(p);
                var m = charT2S[c];
                if (m !== undefined) { out += m; changed = true; } else out += c;
            }
            return changed ? out : s;
        }

        step = 'dom';
        // ---- DOM ----
        var SKIP = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEXTAREA: 1 };
        var HAN = /[一-鿿\uD840-\uD87F]/;
        var ATTRS = ['placeholder', 'title', 'alt', 'aria-label'];

        function convertTextNode(node) {
            try {
                var v = node.nodeValue;
                if (!v || v === node.__gw2t || !HAN.test(v)) return;
                var parent = node.parentNode;
                if (parent && (SKIP[parent.nodeName] === 1 || parent.isContentEditable)) return;
                var nv = s2t(v);
                if (nv !== v) { node.__gw2t = nv; node.nodeValue = nv; api.converted++; }
            } catch (e) { api.errors++; api.last = String(e); }
        }

        function convertAttr(el, name) {
            try {
                var v = el.getAttribute(name);
                if (!v || !HAN.test(v)) return;
                var done = el.__gw2a || (el.__gw2a = {});
                if (v === done[name]) return;
                var nv = s2t(v);
                if (nv !== v) { done[name] = nv; el.setAttribute(name, nv); api.attrs++; }
            } catch (e) { api.errors++; api.last = String(e); }
        }

        function convertAttrs(el) {
            if (!el || !el.getAttribute) return;
            for (var a = 0; a < ATTRS.length; a++) convertAttr(el, ATTRS[a]);
        }

        function convertTree(root) {
            if (!root) return;
            var type = root.nodeType;
            if (type === 3) { convertTextNode(root); return; }
            if (type !== 1 && type !== 9 && type !== 11) return;
            if (type === 1) convertAttrs(root);
            var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, null, false);
            var n;
            while ((n = walker.nextNode())) {
                if (n.nodeType === 3) convertTextNode(n); else convertAttrs(n);
            }
        }

        function convertAll() {
            try {
                convertTree(document);
                if (document.title && HAN.test(document.title)) {
                    var t = s2t(document.title);
                    if (t !== document.title) document.title = t;
                }
            } catch (e) { api.errors++; api.last = String(e); }
        }

        step = 'observer';
        var observer = new MutationObserver(function (list) {
            for (var m = 0; m < list.length; m++) {
                var rec = list[m];
                if (rec.type === 'childList') {
                    for (var a = 0; a < rec.addedNodes.length; a++) convertTree(rec.addedNodes[a]);
                } else if (rec.type === 'characterData') {
                    convertTextNode(rec.target);
                } else if (rec.type === 'attributes') {
                    convertAttr(rec.target, rec.attributeName);
                }
            }
        });
        observer.observe(document, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });

        step = 'inputs';
        // ---- 搜尋框：頁面讀到簡體、畫面顯示繁體 ----
        if (HOOK_INPUTS) {
            try {
                var proto = window.HTMLInputElement && window.HTMLInputElement.prototype;
                var desc = proto && Object.getOwnPropertyDescriptor(proto, 'value');
                if (desc && desc.get && desc.set) {
                    var isTextInput = function (el) {
                        var type = String(el.type || 'text').toLowerCase();
                        return type === 'text' || type === 'search';
                    };
                    Object.defineProperty(proto, 'value', {
                        configurable: true,
                        enumerable: desc.enumerable,
                        get: function () {
                            var v = desc.get.call(this);
                            return (v && isTextInput(this)) ? t2sChars(v) : v;
                        },
                        set: function (v) {
                            desc.set.call(this, (typeof v === 'string' && isTextInput(this)) ? s2tChars(v) : v);
                        }
                    });
                    api.inputHook = true;
                }
            } catch (e) { api.errors++; api.last = 'input:' + e; }
        }

        step = 'initial';
        convertAll();
        document.addEventListener('DOMContentLoaded', convertAll);
        window.addEventListener('load', convertAll);

        step = 'done';
        note('started', 'inputHook=' + api.inputHook + ' rules=' + DICT.length);
    } catch (e) {
        try { window.__gw2S2TError = String(e); } catch (e2) { }
        note('err', e);
    }
}
