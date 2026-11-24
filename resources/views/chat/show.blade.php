@php
    $modeLabels = [
        'autonomous_investigation' => 'Autonomous investigation',
        'guided_secops_copilot' => 'Guided copilot',
        'strict_compliance_audit' => 'Compliance audit',
        'triage_and_containment' => 'Triage & containment',
    ];
@endphp
<x-app-layout>
    <x-slot name="title">{{ $chatSession->title }} · Livewire Workspace</x-slot>
    <x-slot name="section">Livewire Agent</x-slot>
    <x-slot name="breadcrumb">{{ \Illuminate\Support\Str::limit($chatSession->title, 40) }}</x-slot>

    <div class="page-heading">
        <div>
            <p class="eyebrow">CPMK-3 · Pertemuan 12</p>
            <h1>Reactive Agentic AI Workspace</h1>
            <p class="subtitle" style="font-size:14px;color:var(--text-muted)">
                Split-Panel IDE Interface (Livewire 4 + Event Bus + Real-Time wire:poll)
            </p>
        </div>
        <div class="actions">
            <a class="button" href="{{ route('chat.index') }}">Conversations Overview</a>
            <a class="button" href="{{ route('investigations.index') }}">Investigation Workspace</a>
        </div>
    </div>

    {{-- 3-Column Split Panel Agentic AI Workspace (Pertemuan 12 & Challenges 1, 2, 3) --}}
    <div class="agentic-workspace-layout mb-6">
        {{-- Komponen 1: ChatSidebar (wire:dispatch & #[On('message-sent')]) --}}
        <livewire:chat-sidebar :initialSessionId="$chatSession->id" />

        {{-- Komponen 2: ChatBox (wire:model, wire:loading, typewriter effect, MySQL storage) --}}
        <livewire:chat-box :initialSessionId="$chatSession->id" />

        {{-- Komponen 3: CodeVisualizer (Split-panel syntax highlighter & wire:poll.2s) --}}
        <livewire:code-visualizer :initialSessionId="$chatSession->id" />
    </div>

    {{-- Week 9 CPMK-2: Eager Loading vs N+1 Benchmark Inspector --}}
    <details class="panel inspector acc" @if($mode === 'lazy') open @endif>
        <summary>
            <span>Query Inspector · Pertemuan 9 & 12 Optimization</span>
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
                <section class="stat"><div class="stat-label">Total Messages</div><div class="stat-number">{{ $chatSession->chatMessages->count() }}</div></section>
            </div>
            @foreach ($queries as $index => $q)
                <div class="query"><span>#{{ $index + 1 }} · {{ $q['time'] }} ms</span>{{ $q['query'] }}@if(! empty($q['bindings'])) <span>bindings: [{{ implode(', ', array_map(fn ($b) => is_numeric($b) ? $b : "'".$b."'", $q['bindings'])) }}]</span>@endif</div>
            @endforeach
        </div>
    </details>
</x-app-layout>
