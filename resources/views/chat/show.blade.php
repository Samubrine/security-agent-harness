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
            <p class="eyebrow">Conversation</p>
            <h1>{{ $chatSession->title }}</h1>
            <p class="subtitle" style="font-size:14px;color:var(--text-muted)">{{ $modeLabels[$chatSession->agent_mode] ?? $chatSession->agent_mode }} · started {{ $chatSession->created_at->format('d M Y, H:i') }} · {{ ucfirst($chatSession->status) }}</p>
        </div>
        <div class="actions">
            <a class="button" href="{{ route('chat.index') }}">All conversations</a>
            <a class="button" href="{{ route('investigations.index') }}">Investigation workspace</a>
        </div>
    </div>

    <div x-data="agentChat">
    <section class="panel" aria-label="Conversation">
        <div class="thread">
        <div class="conversation">
            @forelse ($messages as $msg)
                @if ($msg->role === 'system')
                    <div class="msg-system" @if($msg->id === $lastId) id="latest" @endif>{{ $msg->content }}</div>
                @elseif ($msg->role === 'user')
                    <div class="msg-user" @if($msg->id === $lastId) id="latest" @endif>
                        <div class="msg-meta">{{ preg_replace('/\s*\(.*\)/', '', $chatSession->user->name ?? 'Operator') }} · {{ $msg->created_at->format('H:i') }}</div>
                        <div class="msg-text">{{ $msg->content }}</div>
                    </div>
                @else
                    <article class="msg-agent" @if($msg->id === $lastId) id="latest" tabindex="-1" @endif aria-label="Agent answer">
                        <div class="msg-meta">
                            <strong>AEGIS</strong>
                            <span>{{ $msg->created_at->format('H:i') }}</span>
                            <span class="badge">{{ number_format($msg->token_count) }} tokens</span>
                            @if ($msg->toolExecutionLogs->isNotEmpty())<span class="badge">{{ $msg->toolExecutionLogs->count() }} tool {{ \Illuminate\Support\Str::plural('call', $msg->toolExecutionLogs->count()) }}</span>@endif
                        </div>

                        @if ($msg->toolExecutionLogs->isNotEmpty())
                            <div class="steps">
                                <div class="steps-title"><span>What the agent did</span><span>tool_execution_logs</span></div>
                                @foreach ($msg->toolExecutionLogs->sortBy('id') as $toolLog)
                                    @include('chat.partials.tool-log', ['toolLog' => $toolLog])
                                @endforeach
                            </div>
                        @endif

                        @if ($msg->reasoning)
                            <details class="reasoning">
                                <summary>Show reasoning</summary>
                                <div class="rendered-report">{!! $md($msg->reasoning) !!}</div>
                            </details>
                        @endif

                        <div class="rendered-report">{!! $md($msg->content) !!}</div>

                        @include('chat.partials.fact-check', ['check' => $msg->claim_check])
                        @if (is_array($msg->pending_action))
                            @include('chat.partials.pending-action', ['action' => $msg->pending_action, 'message' => $msg, 'isLatest' => $msg->id === $lastId])
                        @endif
                    </article>
                @endif
            @empty
                <div class="empty">
                    <span class="empty-icon"><svg class="icon" aria-hidden="true"><use href="#i-shield"/></svg></span>
                    <strong>Ask your first question</strong>
                    <p>Try one of the suggestions below, or describe what you want checked in your own words.</p>
                </div>
            @endforelse
        </div>
        </div>
    </section>

    <section class="composer" aria-label="Message the agent">
      <div class="composer-inner">
        <div class="live" x-ref="live" x-show="busy || error" x-cloak x-transition.opacity.duration.150ms>
            <div class="live-head">
                <span class="live-chip" x-show="busy"><i aria-hidden="true"></i>Live</span>
                <span class="working" x-show="busy" x-text="status">The agent is working.</span>
            </div>
            <ol class="live-steps" aria-live="polite" aria-label="Agent progress">
                <template x-for="(s, i) in steps" :key="i">
                    <li class="live-step" :class="[s.kind, s.state]">
                        <span class="live-dot" aria-hidden="true"></span>
                        <span class="live-label" x-text="s.label + (s.count > 1 ? ' (×' + s.count + ')' : '')"></span>
                        <span class="live-result" x-show="s.result" x-text="s.result"></span>
                    </li>
                </template>
            </ol>
            <p class="field-error" role="alert" x-show="error"><span x-text="error"></span> <button type="button" class="button small" @click="retry()">Try again</button></p>
        </div>
        @error('content')<p class="field-error" role="alert">{{ $message }}</p>@enderror
        <form method="POST" action="{{ route('chat.message', $chatSession->id) }}" @submit.prevent="run($el)" novalidate>
            @csrf
            <div class="chips" x-show="!busy" aria-label="Suggested questions">
                @foreach ([
                    'Is lab-web-01 safe? Check it and explain the most serious risks.',
                    'Was Tomcat on lab-web-01 really patched? Check against the asset inventory.',
                    'Scan the web server.',
                    'Analyse lab-logs. Did someone break in?',
                    'What have we found so far?',
                ] as $prompt)
                    <button type="button" class="button small" @click="$refs.input.value = @js($prompt); invalid = false; $refs.input.focus()">{{ $prompt }}</button>
                @endforeach
            </div>
            <label class="sr-only" for="messageInput">Message</label>
            <div class="compose-box" :class="{ invalid }">
                <textarea id="messageInput" x-ref="input" name="content" rows="1" required maxlength="4000" :readonly="busy"
                    :aria-invalid="invalid" aria-describedby="composer-help"
                    placeholder="Ask the agent, e.g. “Apakah lab-web-01 aman?”"
                    @input="invalid = false; $el.style.height = 'auto'; $el.style.height = Math.min($el.scrollHeight, 180) + 'px'"
                    @keydown.enter="if (!$event.shiftKey && !$event.isComposing) { $event.preventDefault(); run($el.form) }">{{ old('content') }}</textarea>
                <button type="submit" class="button primary" :class="{ 'is-loading': busy, 'is-success': sent }" :disabled="busy"><span>Send</span></button>
            </div>
            <p class="field-error" role="alert" x-show="invalid" x-cloak>Write a question first, at least two characters.</p>
            <p class="hint" id="composer-help">Enter sends · Shift+Enter adds a line · Checks only run against the signed lab scope.</p>
        </form>
      </div>
    </section>
    </div>

    {{-- Week 9 (relational modelling): eager loading vs N+1 on this page's own query. --}}
    <details class="panel inspector acc" @if($mode === 'lazy') open @endif>
        <summary>
            <span>Query inspector · Pertemuan 9</span>
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
