// Live agent turns. A form submitted through run() is sent with `Accept: application/x-ndjson`;
// the server answers with one JSON event per line while the agent works (deciding, running a
// tool, each harness step, checking the answer), and the page shows them as they arrive. When
// the browser cannot stream, the form is submitted normally and the page waits as before.
export default () => ({
    busy: false,
    steps: [],
    error: null,

    async run(form) {
        if (this.busy) return;
        if (form.content && form.content.value.trim().length < 2) return;
        if (!window.fetch || !window.ReadableStream || !window.TextDecoder) {
            this.busy = true;
            form.submit();
            return;
        }
        this.busy = true;
        this.steps = [];
        this.error = null;
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
            this.error = 'Lost the connection while the agent was working. Reload the page to see whether it finished.';
            this.busy = false;
        }
    },

    handle(event) {
        if (event.type === 'done') {
            this.steps.forEach((s) => { if (s.state === 'active') s.state = 'done'; });
            window.location.assign(event.url);
            return;
        }
        if (event.type === 'error') {
            this.error = event.message;
            this.busy = false;
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
