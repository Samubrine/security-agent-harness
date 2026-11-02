@php
    $modeLabels = [
        'autonomous_investigation' => 'Do it for me',
        'guided_secops_copilot' => 'Teach me as you go',
        'strict_compliance_audit' => 'Formal audit',
        'triage_and_containment' => 'What is urgent first',
    ];
    $md = fn ($text) => \Illuminate\Support\Str::markdown((string) $text, ['html_input' => 'escape', 'allow_unsafe_links' => false]);
    $messages = $chatSession->chatMessages->where('role', '!=', 'system')->values();
    $lastId = $messages->last()?->id;
@endphp
<x-app-layout>
    <x-slot name="title">{{ $chatSession->title }}</x-slot>
    <x-slot name="section">AEGIS</x-slot>
    <x-slot name="breadcrumb">{{ \Illuminate\Support\Str::limit($chatSession->title, 48) }}</x-slot>

    <div class="page-heading">
        <div>
            <h1 class="chat-title">{{ $chatSession->title }}</h1>
            <p class="subtitle">{{ $modeLabels[$chatSession->agent_mode] ?? $chatSession->agent_mode }} · started {{ $chatSession->created_at->format('d M Y, H:i') }}</p>
        </div>
        <div class="actions">
            <a class="button" href="{{ route('chat.index') }}">All conversations</a>
            <a class="button" href="{{ route('investigations.index') }}">Investigation workspace</a>
        </div>
    </div>

    <div x-data="{ busy: false, send(form) { if (form.content.value.trim().length < 2) return; this.busy = true; form.submit(); } }">
    <div class="thread">
        @foreach ($messages as $msg)
            @if ($msg->role === 'user')
                <div class="say" @if($msg->id === $lastId) id="latest" @endif>{{ $msg->content }}</div>
            @else
                @php $logs = $msg->toolExecutionLogs->sortBy('id')->values(); @endphp
                <article @if($msg->id === $lastId) id="latest" @endif>
                    <div class="turn-head">
                        <strong>AEGIS agent</strong>
                        <span>{{ $msg->created_at->format('H:i') }}
                            @if ($logs->isNotEmpty()) · it took {{ $logs->count() }} {{ \Illuminate\Support\Str::plural('step', $logs->count()) }} @endif
                            · {{ number_format($msg->token_count) }} tokens</span>
                    </div>

                    @if ($logs->isNotEmpty())
                        <ol class="route" aria-label="What the agent did">
                            @foreach ($logs as $i => $toolLog)
                                @include('chat.partials.stop', ['toolLog' => $toolLog, 'number' => $i + 1])
                            @endforeach
                            <li class="stop">
                                <span class="node answer" aria-hidden="true">✓</span>
                                <div><h4>Put it together in plain words</h4></div>
                            </li>
                        </ol>
                    @else
                        <p class="hint" style="margin:-.3rem 0 .9rem">The agent decided no tool was needed for this one, so it answered directly.</p>
                    @endif

                    <div class="answer-body">
                        <div class="rendered-report">{!! $md($msg->content) !!}</div>
                        @if ($msg->reasoning)
                            <details class="reasoning tech">
                                <summary>Show the model's private reasoning</summary>
                                <div class="rendered-report" style="margin-top:.5rem">{!! $md($msg->reasoning) !!}</div>
                            </details>
                        @endif
                    </div>

                    @if ($msg->id === $lastId && ! empty($msg->suggestions))
                        <div class="next">
                            <span>The agent suggests:</span>
                            @foreach ($msg->suggestions as $suggestion)
                                <form method="POST" action="{{ route('chat.message', $chatSession->id) }}" @submit="busy = true">
                                    @csrf
                                    <input type="hidden" name="content" value="{{ $suggestion }}">
                                    <button type="submit" :disabled="busy">{{ $suggestion }}</button>
                                </form>
                            @endforeach
                        </div>
                    @endif
                </article>
            @endif
        @endforeach
    </div>

    <section class="panel composer">
        @error('content')<p class="field-error" style="margin:0 0 10px">{{ $message }}</p>@enderror
        <form method="POST" action="{{ route('chat.message', $chatSession->id) }}" @submit.prevent="send($el)">
            @csrf
            <div class="working" x-show="busy" x-cloak><span class="spinner"></span><span>The agent is working: choosing what to check, scanning, reading the results. This usually takes under a minute, and the answer will show every step it took.</span></div>
            <div class="chips" x-show="!busy">
                @foreach ([
                    'Is lab-web-01 safe?',
                    'Did anyone try to break into the lab?',
                    'What should I fix first?',
                    'What have we found so far?',
                    'Explain CVE-2021-41773 like I am new to security',
                ] as $prompt)
                    <button type="button" class="button small" @click="$refs.input.value = @js($prompt); $refs.input.focus()">{{ $prompt }}</button>
                @endforeach
            </div>
            <div class="form-row">
                <div style="flex:1">
                    <label class="small-label field-label" for="messageInput">Your message</label>
                    <textarea id="messageInput" x-ref="input" class="field" name="content" rows="2" required maxlength="4000" :readonly="busy"
                        placeholder="Ask a follow-up, e.g. “How do I fix the Tomcat problem?”"
                        @keydown.enter="if (!$event.shiftKey) { $event.preventDefault(); send($el.form) }">{{ old('content') }}</textarea>
                </div>
                <button type="submit" class="button primary" :disabled="busy"><span x-text="busy ? 'Working…' : 'Send'">Send</span></button>
            </div>
            <p class="hint" style="margin-top:8px">Enter to send, Shift+Enter for a new line. The agent only investigates the machines in the signed lab scope.</p>
        </form>
    </section>
    </div>

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
