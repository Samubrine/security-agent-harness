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

    @php $latest = $chatSessions->first(); @endphp
    <section class="hero" aria-labelledby="hero-title">
        <div class="hero-copy">
            <p class="eyebrow">Signed lab scope</p>
            <h1 id="hero-title">Is your lab safe?</h1>
            <p class="lead">Ask in your own words. The agent picks the right checks, runs only what the signed scope allows, and answers from the evidence it collected.</p>
            <div class="actions">
                @if ($latest)<a class="button" href="{{ route('chat.show', $latest->id) }}">Continue last conversation</a>@endif
                <a class="button primary" href="#new" data-focus="#title">Start a conversation</a>
            </div>
        </div>
        <div class="hero-visual" aria-hidden="true">
            <div class="glow"></div>
            @include('partials.scope-map', ['uid' => 'home'])
            @if ($latest)
                <div class="float-card">
                    <span class="kicker">Last conversation</span>
                    <strong>{{ $latest->title }}</strong>
                    <span>{{ $latest->chat_messages_count }} messages · {{ $latest->updated_at->diffForHumans() }}</span>
                    <a href="{{ route('chat.show', $latest->id) }}" tabindex="-1">Open</a>
                </div>
            @endif
        </div>
    </section>

    <div class="stats">
        <section class="stat"><div class="stat-number">{{ $chatSessions->total() }}</div><div class="stat-label">Conversations</div><div class="stat-foot">Private to your account</div></section>
        <section class="stat"><div class="stat-number">{{ $toolCalls }}</div><div class="stat-label">Agent tool calls</div><div class="stat-foot">Each one is logged</div></section>
        <section class="stat"><div class="stat-number">{{ $investigations }}</div><div class="stat-label">Investigations recorded</div><div class="stat-foot"><a class="text-button" href="{{ route('investigations.index') }}">Open workspace</a></div></section>
        <section class="stat"><div class="stat-number" style="font-size:18px;line-height:1.3;margin-top:10px;overflow-wrap:anywhere">{{ config('agent.llm.model') }}</div><div class="stat-label">Language model</div><div class="stat-foot">{{ parse_url(config('agent.llm.base_url'), PHP_URL_HOST) }}</div></section>
    </div>

    <div class="grid">
        <div>
            <section class="panel" aria-labelledby="recent-title">
                <div class="panel-header"><div><p class="eyebrow">Recent</p><h2 id="recent-title">Conversations</h2><p>Most recently active first.</p></div></div>
                @forelse ($chatSessions as $session)
                    @if ($loop->first)<div class="rows">@endif
                    <a class="session-row" href="{{ route('chat.show', $session->id) }}">
                        <span class="severity-dot {{ $session->status === 'active' ? 'on' : '' }}" aria-hidden="true"></span>
                        <span class="finding-info">
                            <strong>{{ $session->title }}</strong>
                            <small>{{ $modes[$session->agent_mode][0] ?? $session->agent_mode }} · {{ $session->chat_messages_count }} messages · {{ $session->updated_at->diffForHumans() }}</small>
                        </span>
                        <span class="chip-status {{ $session->status === 'active' ? '' : 'muted' }}">{{ ucfirst($session->status) }}</span>
                        <span class="arrow" aria-hidden="true">→</span>
                    </a>
                    @if ($loop->last)</div>@endif
                @empty
                    <div class="empty">
                        <span class="empty-icon"><svg class="icon" aria-hidden="true"><use href="#i-shield"/></svg></span>
                        <strong>No conversations yet</strong>
                        <p>Start one and ask something concrete, like whether the web server is safe. The agent shows every step it takes.</p>
                        <a class="button primary" href="#new" data-focus="#title">Start a conversation</a>
                    </div>
                @endforelse
                @if ($chatSessions->hasPages())
                    <div class="section-head" style="border-top:1px solid var(--line)">
                        @if ($chatSessions->previousPageUrl())<a class="text-button" href="{{ $chatSessions->previousPageUrl() }}">Newer</a>@else<span></span>@endif
                        <p>Page {{ $chatSessions->currentPage() }} of {{ $chatSessions->lastPage() }}</p>
                        @if ($chatSessions->nextPageUrl())<a class="text-button" href="{{ $chatSessions->nextPageUrl() }}">Older</a>@else<span></span>@endif
                    </div>
                @endif
            </section>
        </div>

        <div>
            <section class="panel" id="new" aria-labelledby="new-title">
                <div class="panel-header"><div><p class="eyebrow">New</p><h2 id="new-title">Start a conversation</h2><p>Pick how the agent should behave.</p></div></div>
                <form method="POST" action="{{ route('chat.store') }}" class="form-grid" data-validate data-pending="Starting conversation" x-data="{ mode: @js(old('agent_mode', 'autonomous_investigation')), hints: @js(collect($modes)->map(fn ($m) => $m[1])) }">
                    @csrf
                    <div>
                        <label class="small-label field-label" for="title">Title</label>
                        <input class="field" id="title" name="title" required maxlength="255" value="{{ old('title') }}" placeholder="e.g. Is the web server safe?" autocomplete="off" @if($errors->has('title')) aria-invalid="true" @endif>
                        <x-input-error :messages="$errors->get('title')" />
                    </div>
                    <div>
                        <label class="small-label field-label" for="agent_mode">Mode</label>
                        <select class="field" id="agent_mode" name="agent_mode" x-model="mode">
                            @foreach ($modes as $value => [$label, $hint])
                                <option value="{{ $value }}">{{ $label }}</option>
                            @endforeach
                        </select>
                        <p class="hint mode-hint" style="margin-top:8px" x-text="hints[mode]" aria-live="polite"></p>
                    </div>
                    <button class="button primary" type="submit">Start conversation</button>
                </form>
            </section>

            <section class="panel" aria-labelledby="owners-title">
                <div class="panel-header"><div><h2 id="owners-title">Tool calls by handler</h2><p>Who handled your agent's tool calls.</p></div></div>
                <div class="scope">
                    @foreach ($owners as $class => $label)
                        <div>{{ $label }}<b>{{ $byOwner[$class] ?? 0 }}</b></div>
                    @endforeach
                </div>
            </section>
        </div>
    </div>

    <section class="cells" aria-label="Investigation skills" data-reveal>
        @foreach ([
            ['port_scan', 'Port scan', 'i-scan', 'Finds open services and checks their versions against known CVEs.', ['Network scan of one host', 'Version match against NVD data', 'Signed scope only']],
            ['log_analysis', 'Log analysis', 'i-log', 'Reads a log source for brute force, odd logins and reconnaissance.', ['Failed-login bursts', 'Suspicious sign-ins', 'Evidence kept per line']],
            ['version_check', 'Version check', 'i-link', 'Compares what the scan sees with what the asset inventory says is installed.', ['Two independent sources', 'Conflicts are flagged', 'Inventory call needs approval']],
        ] as [$skillKey, $skillTitle, $skillIcon, $skillText, $skillPoints])
            <article class="cell">
                <span class="icon-tile"><svg class="icon" aria-hidden="true"><use href="#{{ $skillIcon }}"/></svg></span>
                <h2>{{ $skillTitle }}</h2>
                <p>{{ $skillText }}</p>
                <ul class="checklist">
                    @foreach ($skillPoints as $point)<li><svg class="icon" aria-hidden="true"><use href="#i-check"/></svg>{{ $point }}</li>@endforeach
                </ul>
                <a class="text-button" href="{{ route('investigations.index', ['skill' => $skillKey, 'new' => 1]) }}#new-run">Run {{ strtolower($skillTitle) }}</a>
            </article>
        @endforeach
    </section>
</x-app-layout>
