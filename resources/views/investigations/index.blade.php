<x-app-layout>
    <x-slot name="title">Investigations</x-slot>
    <x-slot name="section">Workspace</x-slot>
    <x-slot name="breadcrumb">Overview</x-slot>
    <x-slot name="environment">Recorded investigations</x-slot>

    <div id="workspace"
         data-runs-url="{{ route('investigations.runs') }}"
         data-run-url="{{ str_replace('run-PLACEHOLDER', '__RUN__', route('investigations.run', ['run' => 'run-PLACEHOLDER'])) }}">

        <div class="page-heading">
            <div>
                
                <h1 id="page-title">Security investigation overview</h1>
                <p class="subtitle">Evidence-based security investigation dashboard</p>
            </div>
            <div class="actions">
                <button class="button" id="refresh">Refresh records</button>
            </div>
        </div>

        <details class="panel" style="margin:28px 0 0" @if($errors->any() || session('error')) open @endif
                 x-data="{ skill: @js(old('skill', 'port_scan')) }">
            <summary class="inspector-summary" style="cursor:pointer;padding:16px 22px;font-size:12px;font-weight:600;list-style:none">
                + Run a new investigation <span class="hint" style="font-weight:400">— or ask the agent in Conversations and it will pick one for you</span>
            </summary>
            <form method="POST" action="{{ route('investigations.store') }}" class="form-grid" x-data="{ busy: false }" @submit="busy = true">
                @csrf
                @if ($scopeError)
                    <p class="flash error" style="margin:0">{{ $scopeError }}</p>
                @endif
                <div class="form-row">
                    <div>
                        <label class="small-label field-label" for="skill">SKILL</label>
                        <select class="field" id="skill" name="skill" x-model="skill">
                            <option value="port_scan">Port scan: services, versions, known CVEs</option>
                            <option value="log_analysis">Log analysis: brute force, suspicious logins, recon</option>
                            <option value="entry_point">Entry point: correlate scan and log evidence</option>
                        </select>
                    </div>
                    <div x-show="skill !== 'entry_point'">
                        <label class="small-label field-label" for="target">TARGET (SIGNED SCOPE)</label>
                        <select class="field" id="target" name="target" :disabled="skill === 'entry_point'">
                            <template x-if="skill === 'port_scan'">
                                <optgroup label="Network hosts">
                                    @foreach ($scope->networkTargets() as $alias)
                                        <option value="{{ $alias }}" @selected(old('target') === $alias)>{{ $alias }}</option>
                                    @endforeach
                                </optgroup>
                            </template>
                            <template x-if="skill === 'log_analysis'">
                                <optgroup label="Log sources">
                                    @foreach ($scope->logTargets() as $alias)
                                        <option value="{{ $alias }}" @selected(old('target') === $alias)>{{ $alias }}</option>
                                    @endforeach
                                </optgroup>
                            </template>
                        </select>
                    </div>
                    <div style="flex:2">
                        <label class="small-label field-label" for="objective">OBJECTIVE (OPTIONAL)</label>
                        <input class="field" id="objective" name="objective" value="{{ old('objective') }}" placeholder="e.g. Identify version-level weaknesses on the web host">
                    </div>
                    <button class="button primary" type="submit" :disabled="busy">
                        <span x-show="busy" class="spinner" x-cloak></span>
                        <span x-text="busy ? 'Running…' : 'Run investigation'">Run investigation</span>
                    </button>
                </div>
                <p class="hint">Runs the harness against the selected target in the signed lab scope. Findings appear below when it finishes (usually under a minute).</p>
            </form>
        </details>

        <div class="run-toolbar">
            <div><label class="small-label" for="run-select">INVESTIGATION</label><select id="run-select"></select></div>
            <span class="badge" id="run-status">Loading</span>
        </div>
        <div id="message" role="status" aria-live="polite"></div>
        <div id="content"></div>

        <dialog id="detail">
            <div class="dialog-top"><span class="eyebrow">Details of this problem</span><button id="close-detail" class="icon-button" aria-label="Close details">×</button></div>
            <div id="detail-content"></div>
        </dialog>
    </div>

    <x-slot name="scripts">
        @vite('resources/js/workspace.js')
    </x-slot>
</x-app-layout>
