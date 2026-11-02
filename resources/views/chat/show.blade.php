@php
    $modeLabels = [
        'autonomous_investigation' => 'Autonomous investigation',
        'guided_secops_copilot' => 'Guided copilot',
        'strict_compliance_audit' => 'Compliance audit',
        'triage_and_containment' => 'Triage & containment',
    ];
    $md = fn ($text) => \Illuminate\Support\Str::markdown((string) $text, ['html_input' => 'escape', 'allow_unsafe_links' => false]);
    $messages = $chatSession->chatMessages;
    $lastId = $messages->last()?->id;
@endphp
<x-app-layout>
    <x-slot name="title">{{ $chatSession->title }}</x-slot>
    <x-slot name="section">Agent</x-slot>
    <x-slot name="breadcrumb">{{ \Illuminate\Support\Str::limit($chatSession->title, 48) }}</x-slot>

    <div class="page-heading">
        <div>
            <p class="eyebrow">AEGIS / CONVERSATION</p>
            <h1>{{ $chatSession->title }}</h1>
            <p class="subtitle">{{ $modeLabels[$chatSession->agent_mode] ?? $chatSession->agent_mode }} · started {{ $chatSession->created_at->format('d M Y, H:i') }} · {{ ucfirst($chatSession->status) }}</p>
        </div>
        <div class="actions">
            <a class="button" href="{{ route('chat.index') }}">← All conversations</a>
            <a class="button" href="{{ route('investigations.index') }}">Investigation workspace ↗</a>
        </div>
    </div>

    <section class="panel content">
        <div class="conversation">
            @foreach ($messages as $msg)
                @if ($msg->role === 'system')
                    <div class="msg-system" @if($msg->id === $lastId) id="latest" @endif>{{ $msg->content }}</div>
                @elseif ($msg->role === 'user')
                    <div class="msg-user" @if($msg->id === $lastId) id="latest" @endif>
                        <div class="msg-meta">{{ preg_replace('/\s*\(.*\)/', '', $chatSession->user->name ?? 'Operator') }} · {{ $msg->created_at->format('H:i') }}</div>
                        <div class="msg-text">{{ $msg->content }}</div>
                    </div>
                @else
                    <article class="msg-agent" @if($msg->id === $lastId) id="latest" @endif>
                        <div class="msg-meta">
                            <strong style="color:var(--text)">AEGIS agent</strong>
                            <span>{{ $msg->created_at->format('H:i') }}</span>
                            <span>· {{ number_format($msg->token_count) }} tokens</span>
                            @if ($msg->toolExecutionLogs->isNotEmpty())<span>· {{ $msg->toolExecutionLogs->count() }} tool {{ \Illuminate\Support\Str::plural('call', $msg->toolExecutionLogs->count()) }}</span>@endif
                        </div>

                        @if ($msg->toolExecutionLogs->isNotEmpty())
                            <div class="steps">
                                <div class="steps-title"><span>WHAT THE AGENT DID</span><span>tool_execution_logs</span></div>
                                @foreach ($msg->toolExecutionLogs->sortBy('id') as $toolLog)
                                    @include('chat.partials.tool-log', ['toolLog' => $toolLog])
                                @endforeach
                            </div>
                        @endif

                        @if ($msg->reasoning)
                            <details class="reasoning">
                                <summary>Show the model's reasoning</summary>
                                <div class="rendered-report">{!! $md($msg->reasoning) !!}</div>
                            </details>
                        @endif

                        <div class="rendered-report">{!! $md($msg->content) !!}</div>
                    </article>
                @endif
            @endforeach
        </div>
    </section>

    <section class="panel composer" x-data="{ busy: false, send(form) { if (form.content.value.trim().length < 2) return; this.busy = true; form.submit(); } }">
        @error('content')<p class="field-error" style="margin:0 0 10px">{{ $message }}</p>@enderror
        <form method="POST" action="{{ route('chat.message', $chatSession->id) }}" @submit.prevent="send($el)">
            @csrf
            <div class="working" x-show="busy" x-cloak><span class="spinner"></span> The agent is working: choosing tools, running the investigation, reading results. This can take a minute.</div>
            <div class="chips" x-show="!busy">
                @foreach ([
                    'Is lab-web-01 safe? Check it and explain the most serious risks.',
                    'Analyse lab-logs. Did someone break in?',
                    'How could an attacker get into the lab? Correlate everything.',
                    'What have we found so far?',
                    'Explain CVE-2021-41773 in simple terms.',
                ] as $prompt)
                    <button type="button" class="button small" @click="$refs.input.value = @js($prompt); $refs.input.focus()">{{ $prompt }}</button>
                @endforeach
            </div>
            <div class="form-row">
                <div style="flex:1">
                    <label class="small-label field-label" for="messageInput">MESSAGE</label>
                    <textarea id="messageInput" x-ref="input" class="field" name="content" rows="2" required maxlength="4000" :readonly="busy"
                        placeholder="Ask the agent, e.g. “Apakah lab-web-01 aman?”"
                        @keydown.enter="if (!$event.shiftKey) { $event.preventDefault(); send($el.form) }">{{ old('content') }}</textarea>
                </div>
                <button type="submit" class="button primary" :disabled="busy"><span x-text="busy ? 'Working…' : 'Send'">Send</span></button>
            </div>
            <p class="hint" style="margin-top:8px">Enter to send · Shift+Enter for a new line · Investigations only run against the signed lab scope.</p>
        </form>
    </section>

    {{-- Week 9 (relational modelling): eager loading vs N+1 on this page's own query. --}}
    <details class="panel inspector" @if($mode === 'lazy') open @endif>
        <summary>
            <span>Query inspector · Pertemuan 9 (eager loading vs N+1)</span>
            <span class="hint" style="font-weight:400">{{ $queryCount }} queries · {{ $executionTimeMs }} ms</span>
        </summary>
        <div class="inspector-body">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
                <div>
                    <span class="badge">{{ $mode === 'optimized' ? 'Tantangan 2: Teroptimasi' : 'Mode N+1 Unoptimized' }}</span>
                    <p class="hint" style="margin-top:8px">{{ $mode === 'optimized' ? 'Nested Eager Loading Terbukti Bebas N+1 Query' : 'Demonstrasi Masalah N+1 Query (Lazy Loading)' }}:
                        @if ($mode === 'optimized')
                            <code>ChatSession::with(['user', 'chatMessages.toolExecutionLogs.loggable'])</code>
                        @else
                            relations are loaded one by one inside the loop, without <code>with()</code>.
                        @endif
                    </p>
                </div>
                <div class="segmented">
                    <a class="{{ $mode === 'optimized' ? 'on' : '' }}" href="{{ route('chat.show', ['id' => $chatSession->id, 'mode' => 'optimized']) }}">Eager loading</a>
                    <a class="{{ $mode === 'lazy' ? 'on' : '' }}" href="{{ route('chat.show', ['id' => $chatSession->id, 'mode' => 'lazy']) }}">Lazy loading (N+1)</a>
                </div>
            </div>
            <div class="stats">
                <section class="stat"><div class="stat-label">SQL queries</div><div class="stat-number {{ $mode === 'lazy' ? 'critical-text' : 'ok-text' }}">{{ $queryCount }}</div></section>
                <section class="stat"><div class="stat-label">Query time</div><div class="stat-number">{{ $executionTimeMs }}<small style="font-size:12px"> ms</small></div></section>
                <section class="stat"><div class="stat-label">N+1 status</div><div class="stat-number" style="font-size:16px;margin-top:20px">{{ $mode === 'optimized' ? '✓ Bebas N+1 (Pass)' : '✗ Terdeteksi N+1' }}</div></section>
                <section class="stat"><div class="stat-label">Messages / tool logs</div><div class="stat-number">{{ $messages->count() }} / {{ $messages->sum(fn ($m) => $m->toolExecutionLogs->count()) }}</div></section>
            </div>
            @foreach ($queries as $index => $q)
                <div class="query"><span>#{{ $index + 1 }} · {{ $q['time'] }} ms</span>{{ $q['query'] }}@if(! empty($q['bindings'])) <span>bindings: [{{ implode(', ', array_map(fn ($b) => is_numeric($b) ? $b : "'".$b."'", $q['bindings'])) }}]</span>@endif</div>
            @endforeach
        </div>
    </details>
</x-app-layout>
