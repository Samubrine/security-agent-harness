// Live agent turns. A form submitted through run() is sent with `Accept: application/x-ndjson`;
// the server answers with one JSON event per line while the agent works (deciding, running a
// tool, each harness step, checking the answer), and the page shows them as they arrive. When
// the browser cannot stream, the form is submitted normally and the page waits as before.
export default () => ({
    busy: false,
    sent: false,
    invalid: false,
    steps: [],
    error: null,
    status: 'The agent is working.',
    lastForm: null,
    clock: null,

    // Keep the elapsed-time label current while a turn runs (text only, no animation).
    startClock() {
        const began = Date.now();
        const tick = () => {
            const mains = this.steps.filter((s) => s.kind === 'main').length;
            this.status = `Step ${Math.max(1, mains)} · ${Math.round((Date.now() - began) / 1000)}s`;
        };
        tick();
        this.clock = setInterval(tick, 1000);
    },
    stop(state) {
        clearInterval(this.clock);
        this.busy = false;
        window.aegis?.agent('idle');
        if (state === 'error') window.aegis?.announce('The agent could not finish. ' + (this.error || ''));
    },
    retry() { if (this.lastForm) this.run(this.lastForm); },

    async run(form) {
        if (this.busy) return;
        if (form.content && form.content.value.trim().length < 2) {
            this.invalid = true;
            form.content.focus();
            return;
        }
        this.invalid = false;
        this.lastForm = form;
        if (!window.fetch || !window.ReadableStream || !window.TextDecoder) {
            this.busy = true;
            form.submit();
            return;
        }
        this.busy = true;
        this.steps = [];
        this.error = null;
        window.aegis?.agent('busy');
        window.aegis?.announce('The agent is working.');
        this.startClock();
        this.$nextTick(() => this.$refs.live?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }));
        try {
            const res = await fetch(form.action, {
                method: 'POST',
                body: new FormData(form),
                headers: { Accept: 'application/x-ndjson' },
            });
            if (!res.body || !(res.headers.get('content-type') || '').includes('ndjson')) {
                window.location.assign(res.url || window.location.href);
                return;
            }
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                let newline;
                while ((newline = buffer.indexOf('\n')) >= 0) {
                    const line = buffer.slice(0, newline).trim();
                    buffer = buffer.slice(newline + 1);
                    if (line) this.handle(JSON.parse(line));
                }
            }
        } catch (e) {
            this.error = 'Lost the connection while the agent was working. Your message is kept. Try again, or reload to see whether it finished.';
            this.stop('error');
        }
    },

    handle(event) {
        if (event.type === 'done') {
            this.steps.forEach((s) => { if (s.state === 'active') s.state = 'done'; });
            clearInterval(this.clock);
            this.sent = true;
            window.aegis?.announce('Answer ready.');
            setTimeout(() => window.location.assign(event.url), 350);
            return;
        }
        if (event.type === 'error') {
            this.error = event.message;
            this.stop('error');
            return;
        }
        if (!event.label) return;
        if (event.type === 'tool_finished') {
            const step = [...this.steps].reverse().find((s) => s.tool === event.tool && s.state === 'active');
            if (step) {
                step.state = event.ok ? 'done' : 'failed';
                step.result = event.label;
            }
            this.steps.forEach((s) => { if (s.kind === 'sub' && s.state === 'active') s.state = 'done'; });
            return;
        }
        const kind = event.type === 'harness' ? 'sub' : 'main';
        const last = this.steps[this.steps.length - 1];
        if (last && last.label === event.label) {
            last.count += 1;
            return;
        }
        // A new step finishes the previous one at the same level; a harness step never closes the
        // tool call it belongs to.
        this.steps.forEach((s) => {
            if (s.state === 'active' && (s.kind === kind || kind === 'main') && !(kind === 'sub' && s.tool)) s.state = 'done';
            if (kind === 'main' && s.state === 'active') s.state = 'done';
        });
        this.steps.push({ label: event.label, kind, tool: event.tool || null, state: 'active', result: null, count: 1 });
    },
});
