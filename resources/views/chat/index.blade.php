@use('App\Support\Plain')
@php
    $styles = [
        'autonomous_investigation' => ['Do it for me', 'Runs checks and lookups on its own, then explains.'],
        'guided_secops_copilot' => ['Teach me as you go', 'Explains every term and why each step matters.'],
        'triage_and_containment' => ['What is urgent first', 'Puts the most dangerous problems on top with first fixes.'],
        'strict_compliance_audit' => ['Formal audit', 'Conservative: only what the evidence confirms.'],
    ];
    $owners = [
        \App\Models\SecurityScanner::class => 'Network scans',
        \App\Models\LogAnalyzer::class => 'Log analysis',
        \App\Models\KnowledgeSource::class => 'Public database lookups',
        \App\Models\MalwareScanner::class => 'Malware scans',
    ];
    $cveLookups = $byOwner[\App\Models\KnowledgeSource::class] ?? 0;
    $examples = [
        'Is lab-web-01 safe?',
        'Did anyone try to break into the lab?',
        'What should I fix first?',
        'Explain CVE-2021-41773 like I am new to security',
    ];
@endphp
<x-app-layout>
    <x-slot name="title">Home</x-slot>
    <x-slot name="section">AEGIS</x-slot>
    <x-slot name="breadcrumb">Home</x-slot>

    <section class="hero" x-data="{ busy: false }">
        <h1>Is your lab safe?</h1>
        <p class="lead">Ask in your own words. The agent works out what to check, scans the lab, looks things up in the public vulnerability database, and explains what it found without the jargon.</p>

        <form class="ask" method="POST" action="{{ route('chat.ask') }}" x-ref="askForm" @submit="busy = true">
            @csrf
            <label class="sr-only" for="question" style="position:absolute;left:-9999px">Your question</label>
            <textarea id="question" name="content" x-ref="q" rows="2" required minlength="2" maxlength="4000" :readonly="busy"
                placeholder="For example: Is lab-web-01 safe?"
                @keydown.enter="if (!$event.shiftKey) { $event.preventDefault(); $refs.askForm.requestSubmit() }">{{ old('content') }}</textarea>
            @error('content')<p class="field-error">{{ $message }}</p>@enderror
            <div class="ask-actions">
                <div class="chips" x-show="!busy">
                    @foreach ($examples as $example)
                        <button type="button" class="button small" @click="$refs.q.value = @js($example); $refs.q.focus()">{{ $example }}</button>
                    @endforeach
                </div>
                <div style="display:flex;gap:.6rem;align-items:center">
                    <select class="field" name="agent_mode" aria-label="How should the agent answer?" style="width:auto;padding:.5rem .7rem;font-size:.9rem" :disabled="busy">
                        @foreach ($styles as $value => [$label])
                            <option value="{{ $value }}">{{ $label }}</option>
                        @endforeach
                    </select>
                    <button class="button primary" type="submit" :disabled="busy"><span x-text="busy ? 'Working…' : 'Ask the agent'">Ask the agent</span></button>
                </div>
            </div>
        </form>

        <div class="ask-sub">
            <form method="POST" action="{{ route('chat.checkup') }}" @submit="busy = true">
                @csrf
                <button class="button" type="submit" :disabled="busy">Run a full check-up</button>
            </form>
            <p class="hint">No question needed: the agent decides what to scan, looks up the worst flaws and writes you a briefing.</p>
        </div>

        <p class="working" x-show="busy" x-cloak style="margin-top:1.2rem;display:flex;gap:.7rem;align-items:flex-start"><span class="spinner"></span><span>The agent is working: choosing what to check, scanning, reading the results. This usually takes under a minute. You will land on its answer, with every step it took.</span></p>
    </section>

    <section class="band">
        <h2>Where the lab stands</h2>
        <p class="band-sub">From the most recent check of each kind. Open any problem to see the proof behind it.</p>
        <div class="status-grid">
            <div class="verdict {{ $verdict['level'] }}">
                <span class="pill {{ $verdict['level'] }}">{{ $verdict['level'] === 'unknown' ? 'No data' : ucfirst($verdict['level'] === 'ok' ? 'good' : $verdict['level']) }}</span>
                <h3>{{ $verdict['headline'] }}</h3>
                <p>{{ $verdict['detail'] }}</p>
                @if ($posture['checked'])
                    <div class="counts">
                        <span><b>{{ $posture['counts']['critical'] ?? 0 }}</b>fix now</span>
                        <span><b>{{ $posture['counts']['high'] ?? 0 }}</b>fix soon</span>
                        <span><b>{{ ($posture['counts']['medium'] ?? 0) + ($posture['counts']['low'] ?? 0) }}</b>worth a look</span>
                    </div>
                @endif
            </div>
            <div>
                @forelse (array_slice($posture['problems'], 0, 4) as $problem)
                    @php [$label] = Plain::severity($problem['severity'] ?? null); @endphp
                    <div class="problem">
                        <span class="pill {{ $problem['severity'] ?? 'info' }}">{{ $label }}</span>
                        <strong title="{{ $problem['title'] }}">{{ Plain::findingTitle($problem['title']) }}</strong>
                        <small>{{ Plain::status($problem['status'] ?? null) }} ·
                            <a class="step-link" href="{{ route('investigations.index', ['run' => $problem['run_id'], 'view' => 'findings']) }}" style="text-decoration:underline">see the proof</a></small>
                    </div>
                @empty
                    <p class="hint" style="font-size:1rem">Nothing has been checked yet. Ask a question above or run a full check-up.</p>
                @endforelse
                @if (count($posture['problems']) > 4)
                    <p class="hint" style="margin-top:.8rem"><a class="step-link" style="text-decoration:underline" href="{{ route('investigations.index') }}">and {{ count($posture['problems']) - 4 }} more in the investigation workspace</a></p>
                @endif
            </div>
        </div>
    </section>

    <section class="band">
        <h2>How this agent works</h2>
        <p class="band-sub">It is not a script. A language model reads your question and chooses its own tools, in its own order, using each result to pick the next step. These are the real numbers from your account.</p>
        <ol class="loop">
            <li><strong>Understands</strong><span>Reads your question and knows which machines it may touch.</span><em>{{ $chatSessions->total() }} {{ \Illuminate\Support\Str::plural('conversation', $chatSessions->total()) }}</em></li>
            <li><strong>Decides</strong><span>Picks the tools and the order itself, and explains why before each one.</span><em>{{ $toolCalls }} {{ \Illuminate\Support\Str::plural('choice', $toolCalls) }} made</em></li>
            <li><strong>Acts</strong><span>Scans machines, reads logs, asks the public NIST vulnerability database.</span><em>{{ $investigations }} {{ \Illuminate\Support\Str::plural('investigation', $investigations) }} · {{ $cveLookups }} {{ \Illuminate\Support\Str::plural('lookup', $cveLookups) }}</em></li>
            <li><strong>Remembers</strong><span>Reuses earlier findings instead of scanning again, and keeps the whole chat in mind.</span><em>{{ $investigations }} on file</em></li>
        </ol>
        <div class="guard">
            <strong>Allowed to touch only:</strong>
            @forelse ($scope as $alias => $kind)
                <span class="pill info" title="{{ $kind }}">{{ $alias }}</span>
            @empty
                <span class="hint">No signed scope found yet. Run <code>python scripts/setup.py</code>.</span>
            @endforelse
            <span class="hint">Anything else is refused ({{ $stoppedCalls }} {{ \Illuminate\Support\Str::plural('call', $stoppedCalls) }} stopped so far).</span>
        </div>
    </section>

    @if ($recentLogs->isNotEmpty())
        <section class="band">
            <h2>What the agent did lately</h2>
            <ul class="feed">
                @foreach ($recentLogs as $log)
                    <li>
                        <strong>{{ Plain::toolTitle($log) }}</strong>
                        <time datetime="{{ $log->created_at->toIso8601String() }}">{{ $log->created_at->diffForHumans() }}</time>
                        <small class="{{ $log->status === 'success' ? '' : 'bad' }}">{{ Plain::toolOutcome($log) }}</small>
                    </li>
                @endforeach
            </ul>
        </section>
    @endif

    <section class="band">
        <h2>Your conversations</h2>
        <div class="chat-list">
            @forelse ($chatSessions as $session)
                <a href="{{ route('chat.show', $session->id) }}">
                    <span><strong>{{ $session->title }}</strong><small>{{ $styles[$session->agent_mode][0] ?? $session->agent_mode }} · {{ $session->updated_at->diffForHumans() }}</small></span>
                    <small>{{ $session->chat_messages_count }} messages</small>
                </a>
            @empty
                <p class="hint" style="font-size:1rem">No conversations yet. Ask your first question above.</p>
            @endforelse
        </div>
        @if ($chatSessions->hasPages())
            <div style="display:flex;justify-content:space-between;margin-top:1rem;font-size:.9rem">
                @if ($chatSessions->previousPageUrl())<a class="text-button" href="{{ $chatSessions->previousPageUrl() }}">Newer</a>@else<span></span>@endif
                <span class="hint">Page {{ $chatSessions->currentPage() }} of {{ $chatSessions->lastPage() }}</span>
                @if ($chatSessions->nextPageUrl())<a class="text-button" href="{{ $chatSessions->nextPageUrl() }}">Older</a>@else<span></span>@endif
            </div>
        @endif
    </section>

    <details class="more">
        <summary>For the course: tool calls by handler and manual chat setup</summary>
        <div class="grid" style="margin-top:1rem">
            <section class="panel">
                <div class="panel-header"><div><h2>Tool calls by handler</h2><p>Polymorphic <code>loggable</code> owners of the agent's tool calls.</p></div></div>
                <div class="scope">
                    @foreach ($owners as $class => $label)
                        <div>{{ $label }}<b>{{ $byOwner[$class] ?? 0 }}</b></div>
                    @endforeach
                    <div>Model<b>{{ config('agent.llm.model') }}</b></div>
                </div>
            </section>
            <section class="panel">
                <div class="panel-header"><div><h2>New conversation</h2><p>Create an empty chat and pick its style.</p></div></div>
                <form method="POST" action="{{ route('chat.store') }}" class="form-grid">
                    @csrf
                    <div>
                        <label class="small-label field-label" for="title">Title</label>
                        <input class="field" id="title" name="title" required maxlength="255" value="{{ old('title') }}" placeholder="e.g. Is the web server safe?">
                        <x-input-error :messages="$errors->get('title')" />
                    </div>
                    <div>
                        <label class="small-label field-label" for="agent_mode">Style</label>
                        <select class="field" id="agent_mode" name="agent_mode">
                            @foreach ($styles as $value => [$label, $hint])
                                <option value="{{ $value }}">{{ $label }}: {{ $hint }}</option>
                            @endforeach
                        </select>
                    </div>
                    <button class="button" type="submit">Start empty conversation</button>
                </form>
            </section>
        </div>
    </details>
</x-app-layout>
