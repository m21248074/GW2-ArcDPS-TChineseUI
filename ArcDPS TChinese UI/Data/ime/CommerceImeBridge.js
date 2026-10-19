(function installCommerceIme() {
    'use strict';
    if (!/^(tradingpost|gemstore)-[a-z0-9-]+\.ncplatform\.net$/i.test(location.hostname)) return;
    var n = window.native;
    if (!n || typeof n.call !== 'function' || typeof n.on !== 'function') return;
    if (window.__gw2CommerceImeTest) return;
    var status = window.__gw2CommerceImeTest = { state: 'checking-language', version: 6, documents: 0, focusRepairs: 0 };
    // Diagnostic probe. CEF persists localStorage to disk (leveldb under the
    // gw2cache folder), so writing the state machine here gives us a channel
    // that survives the session. The reader is a plain file scan for the origin
    // key, so nothing else is needed to observe it.
    var probeSeq = 0;
    function probe(what, extra) {
        try {
            var rec = { seq: ++probeSeq, what: what, state: status.state };
            if (extra !== undefined) rec.v = extra;
            var prev = JSON.parse(localStorage.getItem('gw2ime.trace') || '[]');
            if (!(prev instanceof Array)) prev = [];
            prev.push(rec);
            while (prev.length > 60) prev.shift();
            localStorage.setItem('gw2ime.trace', JSON.stringify(prev));
        } catch (_) { }
    }
    function describe(value) {
        try { return JSON.stringify(value); } catch (_) { return String(value); }
    }
    probe('installed', { host: location.hostname, href: String(location.href).slice(0, 160), ver: status.version });
    n.call('GetStats').then(function (stats) {
        var language = stats && (stats.language || stats.Language || stats.lang);
        status.statsLanguage = language === undefined ? null : String(language);
        probe('stats', { raw: describe(stats), language: status.statsLanguage });
        if (!stats || String(language).toLowerCase().indexOf('zh') !== 0) {
            // This used to return here, which made a changed or differently
            // shaped GetStats result silently disable the whole feature. Record
            // it and keep going: the page only renders in Chinese because the
            // unlock already worked, so attempting ImeEnable is harmless.
            probe('language-not-zh-continue', { language: status.statsLanguage });
        }
        // Keep the existing official backend. Only add focus/selection bridging
        // to commerce documents; no credentials or input contents are logged.
        var input = null, previous = null, frame = 0, generation = 0, ready = false;
        var repaired = new WeakSet();
        var repairPending = new WeakSet(), composing = false, textRevision = 0;
        function call(name) {
            var args = Array.prototype.slice.call(arguments, 1);
            try {
                var result = n.call.apply(n, [name].concat(args));
                if (result && result.catch) result.catch(function (reason) {
                    status.state = 'backend-error';
                    probe('call-rejected', { name: name, error: describe(reason) });
                });
                return result;
            } catch (error) {
                status.state = 'backend-error';
                probe('call-threw', { name: name, error: describe(error) });
            }
        }
        function eligible(el) {
            return el && !el.disabled && !el.readOnly && /^(INPUT|TEXTAREA)$/.test(el.tagName) &&
                !/^(password|number|range|checkbox|radio|button|submit)$/i.test(el.type || '') &&
                typeof el.selectionStart === 'number' && typeof el.selectionEnd === 'number';
        }
        function sync() {
            frame = 0;
            if (!input) return;
            var rect = input.getBoundingClientRect();
            // Same-origin embedded search frames use the same native browser.
            // Translate their rectangle into the main frame's coordinates.
            var owner = input.ownerDocument && input.ownerDocument.defaultView;
            var left = rect.left, top = rect.top;
            try {
                while (owner && owner !== window && owner.frameElement) {
                    var container = owner.frameElement, bounds = container.getBoundingClientRect();
                    left += bounds.left + (container.clientLeft || 0);
                    top += bounds.top + (container.clientTop || 0);
                    owner = container.ownerDocument.defaultView;
                }
            } catch (_) { status.state = 'frame-unavailable'; }
            var value = input.value, start = input.selectionStart, end = input.selectionEnd;
            var backward = input.selectionDirection === 'backward', scale = n.scale || 1;
            if (!previous || previous.value !== value) call('ImeSetText', value);
            if (!previous || previous.start !== start || previous.end !== end || previous.backward !== backward)
                call('ImeSetSelection', backward ? end : start, backward ? start : end);
            var dimensions = [left, top, rect.width * scale, rect.height * scale];
            if (!previous || previous.dimensions.join(',') !== dimensions.join(','))
                call('ImeSetRectDim', { left: dimensions[0], top: dimensions[1], width: dimensions[2], height: dimensions[3] });
            previous = { value: value, start: start, end: end, backward: backward, dimensions: dimensions };
            frame = requestAnimationFrame(sync);
        }
        function focus(el) {
            if (!eligible(el)) { probe('focus-ineligible', { tag: el && el.tagName, type: el && el.type }); return; }
            if (input === el) return;
            blur(); input = el; previous = null;
            var session = ++generation;
            ready = false; status.state = 'binding';
            // Let the DOM focus handlers and the browser's native focus finish
            // before enabling TSF. Otherwise the first click can overwrite it.
            frame = requestAnimationFrame(function () {
                frame = 0;
                if (session !== generation || input !== el) return;
                Promise.resolve(call('ImeEnable')).then(function () {
                    if (session !== generation || input !== el) return;
                    // Seed the current value and caret before accepting native
                    // notifications left over from the previous focused field.
                    sync(); ready = true; status.state = 'focused';
                    probe('ime-enabled', { tag: el.tagName, type: el.type });
                }, function (reason) {
                    if (session === generation) status.state = 'backend-error';
                    probe('ime-enable-failed', { error: describe(reason) });
                });
            });
        }
        function blur() {
            if (!input) return;
            ++generation; ready = false; composing = false; input = null; previous = null;
            if (frame) cancelAnimationFrame(frame);
            frame = 0; call('ImeDisable'); status.state = 'ready';
        }
        var documents = [], frames = [];
        function repairFirstClick(doc, el) {
            if (!eligible(el) || repaired.has(el) || repairPending.has(el)) return;
            var session = generation, revision = textRevision;
            repairPending.add(el);
            // Run after the click handlers have opened the recommendations.
            // One genuine DOM blur/focus cycle reproduces the tested workaround;
            // do not retry periodically or move focus after the user starts typing.
            requestAnimationFrame(function () { requestAnimationFrame(function () {
                repairPending.delete(el);
                if (session !== generation || doc.activeElement !== el || input !== el ||
                    composing || revision !== textRevision || el.isConnected === false) return;
                repaired.add(el);
                var start = el.selectionStart, end = el.selectionEnd, direction = el.selectionDirection;
                el.blur();
                if (doc.activeElement && doc.activeElement !== el &&
                    doc.activeElement !== doc.body && doc.activeElement !== doc.documentElement) return;
                el.focus({ preventScroll: true });
                if (doc.activeElement === el) {
                    el.setSelectionRange(start, end, direction);
                    focus(el); status.focusRepairs++;
                }
            }); });
        }
        function attach(doc) {
            if (!doc || documents.indexOf(doc) !== -1) return;
            documents.push(doc); status.documents = documents.length;
            doc.addEventListener('focusin', function (event) { focus(event.target); }, true);
            doc.addEventListener('focusout', function (event) { if (event.target === input) blur(); }, true);
            doc.addEventListener('click', function (event) { repairFirstClick(doc, event.target); }, true);
            doc.addEventListener('compositionstart', function (event) { if (event.target === input) composing = true; }, true);
            doc.addEventListener('compositionend', function (event) { if (event.target === input) composing = false; }, true);
            doc.addEventListener('keydown', function (event) { if (event.target === input) textRevision++; }, true);
            doc.addEventListener('input', function (event) { if (event.target === input) textRevision++; }, true);
            doc.addEventListener('visibilitychange', function () { if (doc.hidden && input && input.ownerDocument === doc) blur(); }, true);
            function visit(frame) { try { attach(frame.contentDocument); } catch (_) {} }
            function scan() {
                if (!doc.querySelectorAll) return;
                var list = doc.querySelectorAll('iframe');
                for (var i = 0; i < list.length; i++) {
                    var frame = list[i];
                    if (frames.indexOf(frame) === -1) {
                        frames.push(frame);
                        (function (f) { f.addEventListener('load', function () { visit(f); }); }(frame));
                    }
                    visit(frame);
                }
            }
            scan();
            if (typeof MutationObserver === 'function' && doc.documentElement)
                new MutationObserver(scan).observe(doc.documentElement, { childList: true, subtree: true });
        }
        attach(document);
        window.addEventListener('blur', function (event) { if (event.target === window) blur(); }, true);
        window.addEventListener('focus', function (event) { if (event.target === window) focus(document.activeElement); }, true);
        window.addEventListener('pagehide', blur, true);
        n.on('ImeTextStore', function (event) {
            probe('textstore', { raw: describe(event) });
            if (!input || !ready || !event) return;
            // Two payload shapes are possible and both are accepted:
            //  * { text, selection } -- the shape the official gw2/ui/ime module
            //    adapter emits
            //  * { caret, selStart, selEnd, interimChar } -- the field names that
            //    sit next to ImeTextStore in the client's binding name table
            // The previous guard only tested event.text, so if the native event
            // carries the second shape the handler always returned and composed
            // text was never written back. Prefer an explicit text when present,
            // otherwise splice the interim text into the current value.
            var shape = typeof event.text === 'string' ? 'text' : 'interim';
            var value = input.value;
            var min = Number(event.selStart), max = Number(event.selEnd);
            if (!isFinite(min)) min = 0;
            if (!isFinite(max)) max = min;
            min = Math.max(0, Math.min(value.length, min));
            max = Math.max(min, Math.min(value.length, max));
            var interim = typeof event.interimChar === 'string' ? event.interimChar : '';
            var text = shape === 'text' ? event.text : value.slice(0, min) + interim + value.slice(max);
            var changed = text !== value;
            if (changed) { textRevision++; input.value = text; }
            var caret = Number(event.caret);
            if (!isFinite(caret)) caret = min + interim.length;
            caret = Math.max(0, Math.min(input.value.length, caret));
            input.setSelectionRange(caret, caret, 'forward');
            if (changed) input.dispatchEvent(new Event('input', { bubbles: true }));
            probe('textstore-applied', { shape: shape, changed: changed, caret: caret });
        });
        status.state = 'ready'; probe('ready', { active: !!document.activeElement });
        focus(document.activeElement);
    }).catch(function (error) {
        status.state = 'stats-error'; probe('stats-error', { error: String(error) });
    });
}());
