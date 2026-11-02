@php
    $modes = [
        'autonomous_investigation' => ['Autonomous investigation', 'Runs investigations and lookups on its own, then chains follow-ups.'],
        'guided_secops_copilot' => ['Guided copilot', 'Explains security terms in plain language as it works. Good for learning.'],
        'strict_compliance_audit' => ['Compliance audit', 'Formal and conservative; labels anything unverified and maps issues to CWE.'],
        'triage_and_containment' => ['Triage & containment', 'Prioritises what is urgent or exploited in the wild, with first containment steps.'],
    ];
    $owners = [
        \App\Models\SecurityScanner::class => 'Security scanners',
        \App\Models\LogAnalyzer::class => 'Log analyzers',
        \App\Models\KnowledgeSource::class => 'Knowledge sources',
        \App\Models\MalwareScanner::class => 'Malware scanners',
    ];
@endphp
<x-app-layout>
    <x-slot name="title">Conversations</x-slot>
    <x-slot name="section">Agent</x-slot>
    <x-slot name="breadcrumb">Conversations</x-slot>

    <div class="page-heading">
        <div>
            <p class="eyebrow">AEGIS / AGENT</p>
            <h1>Agentic AI Chat Sessions</h1>
            <p class="subtitle">Ask in plain language. The agent decides which investigations to run and what public vulnerability data to look up, then answers from that evidence.</p>
        </div>
    </div>

    <div class="stats content">
        <section class="stat"><div class="stat-label">Conversations</div><div class="stat-number">{{ $chatSessions->total() }}</div><div class="stat-foot">Private to your account</div></section>
        <section class="stat"><div class="stat-label">Agent tool calls</div><div class="stat-number">{{ $toolCalls }}</div><div class="stat-foot">Logged per message (polymorphic)</div></section>
        <section class="stat"><div class="stat-label">Investigations recorded</div><div class="stat-number">{{ $investigations }}</div><div class="stat-foot"><a class="text-button" href="{{ route('investigations.index') }}">Open workspace ↗</a></div></section>
        <section class="stat"><div class="stat-label">Model</div><div class="stat-number" style="font-size:20px;margin-top:20px">{{ config('agent.llm.model') }}</div><div class="stat-foot">{{ parse_url(config('agent.llm.base_url'), PHP_URL_HOST) }}</div></section>
    </div>

    <div class="grid">
        <div>
            <section class="panel">
                <div class="panel-header"><div><h2>Conversations</h2><p>Most recently active first.</p></div></div>
                @forelse ($chatSessions as $session)
                    <a class="session-row" href="{{ route('chat.show', $session->id) }}">
                        <span class="severity-dot {{ $session->status === 'active' ? '' : 'info' }}" style="{{ $session->status === 'active' ? 'background:var(--accent)' : '' }}"></span>
                        <span class="finding-info">
                            <strong>{{ $session->title }}</strong>
                            <small>{{ $modes[$session->agent_mode][0] ?? $session->agent_mode }} · {{ $session->chat_messages_count }} messages · {{ $session->updated_at->diffForHumans() }}</small>
                        </span>
                        <span class="arrow">↗</span>
                    </a>
                @empty
                    <div class="empty">No conversations yet. Start one on the right.</div>
                @endforelse
                @if ($chatSessions->hasPages())
                    <div style="padding:14px 22px;border-top:1px solid var(--line);display:flex;justify-content:space-between;font-size:11px">
                        @if ($chatSessions->previousPageUrl())<a class="text-button" href="{{ $chatSessions->previousPageUrl() }}">← Newer</a>@else<span></span>@endif
                        <span class="hint">Page {{ $chatSessions->currentPage() }} of {{ $chatSessions->lastPage() }}</span>
                        @if ($chatSessions->nextPageUrl())<a class="text-button" href="{{ $chatSessions->nextPageUrl() }}">Older →</a>@else<span></span>@endif
                    </div>
                @endif
            </section>
        </div>

        <div>
            <section class="panel">
                <div class="panel-header"><div><h2>New conversation</h2><p>Pick how the agent should behave.</p></div></div>
                <form method="POST" action="{{ route('chat.store') }}" class="form-grid" x-data="{ mode: @js(old('agent_mode', 'autonomous_investigation')), hints: @js(collect($modes)->map(fn ($m) => $m[1])) }">
                    @csrf
                    <div>
                        <label class="small-label field-label" for="title">TITLE</label>
                        <input class="field" id="title" name="title" required maxlength="255" value="{{ old('title') }}" placeholder="e.g. Is the web server safe?">
                        <x-input-error :messages="$errors->get('title')" />
                    </div>
                    <div>
                        <label class="small-label field-label" for="agent_mode">MODE</label>
                        <select class="field" id="agent_mode" name="agent_mode" x-model="mode">
                            @foreach ($modes as $value => [$label, $hint])
                                <option value="{{ $value }}">{{ $label }}</option>
                            @endforeach
                        </select>
                        <p class="hint" style="margin-top:8px" x-text="hints[mode]"></p>
                    </div>
                    <button class="button primary" type="submit">Start conversation</button>
                </form>
            </section>

            <section class="panel">
                <div class="panel-header"><div><h2>Tool calls by handler</h2><p>Polymorphic <code>loggable</code> owners of your agent's tool calls.</p></div></div>
                <div class="scope">
                    @foreach ($owners as $class => $label)
                        <div>{{ $label }}<b>{{ $byOwner[$class] ?? 0 }}</b></div>
                    @endforeach
                </div>
            </section>
        </div>
    </div>
</x-app-layout>
