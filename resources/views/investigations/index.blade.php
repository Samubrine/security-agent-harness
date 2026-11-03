<x-app-layout>
    <x-slot name="title">Investigations</x-slot>
    <x-slot name="section">Workspace</x-slot>
    <x-slot name="breadcrumb">Overview</x-slot>
    <x-slot name="environment">RECORDED INVESTIGATIONS</x-slot>

    <div id="workspace"
         data-runs-url="{{ route('investigations.runs') }}"
         data-run-url="{{ str_replace('run-PLACEHOLDER', '__RUN__', route('investigations.run', ['run' => 'run-PLACEHOLDER'])) }}">

        <div class="page-heading">
            <div>
                <p class="eyebrow">Investigation workspace</p>
                <h1 id="page-title">Security investigation overview</h1>
                <p class="subtitle">Findings, evidence and the full trace of every recorded run.</p>
            </div>
            <div class="actions">
                <button class="button" id="refresh" type="button">Refresh records</button>
            </div>
        </div>

        @php $openNew = $errors->any() || session('error') || request()->boolean('new'); @endphp
        <section class="panel" id="new-run" x-data="{ open: @js($openNew), skill: @js(old('skill', in_array(request('skill'), ['port_scan','log_analysis','entry_point','version_check'], true) ? request('skill') : 'port_scan')) }" x-init="if (open && location.hash === '#new-run') $nextTick(() => $el.scrollIntoView({ block: 'start' }))">
            <button type="button" class="accordion-head" @click="open = !open" :aria-expanded="open" aria-controls="new-run-panel">
                <span><strong>New investigation</strong><span>Or ask the agent in Conversations and it will pick the checks for you.</span></span>
                <svg class="icon" aria-hidden="true"><use href="#i-chevron"/></svg>
            </button>
            <div id="new-run-panel" class="accordion-panel" :class="{ 'is-open': open }" :inert="!open">
              <div>
                <form method="POST" action="{{ route('investigations.store') }}" class="form-grid" data-validate data-pending="Running investigation. This usually takes under a minute.">
                    @csrf
                    @if ($scopeError)
                        <p class="banner" style="margin:0" role="alert">{{ $scopeError }}</p>
                    @endif
                    <div class="form-row">
                        <div>
                            <label class="small-label field-label" for="skill">Skill</label>
                            <select class="field" id="skill" name="skill" x-model="skill">
                                <option value="port_scan">Port scan: services, versions, known CVEs</option>
                                <option value="log_analysis">Log analysis: brute force, suspicious logins, recon</option>
                                <option value="entry_point">Entry point: correlate scan and log evidence</option>
                                <option value="version_check">Version check: scan vs asset inventory (MCP server)</option>
                            </select>
                        </div>
                        <div x-show="skill !== 'entry_point'">
                            <label class="small-label field-label" for="target">Target (signed scope)</label>
                            <select class="field" id="target" name="target" :disabled="skill === 'entry_point'">
                                <template x-if="skill === 'port_scan' || skill === 'version_check'">
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
                    </div>
                    <div>
                        <label class="small-label field-label" for="objective">Objective (optional)</label>
                        <input class="field" id="objective" name="objective" value="{{ old('objective') }}" placeholder="e.g. Identify version-level weaknesses on the web host" maxlength="500" autocomplete="off">
                        <x-input-error :messages="$errors->get('objective')" />
                    </div>
                    <label class="check-label"><input type="checkbox" name="approve" value="1"> <span>Approve steps that need a human OK, for example calling the asset inventory MCP server. Unticked, those steps are skipped and recorded as gaps.</span></label>
                    <div class="actions">
                        <button class="button primary" type="submit">Run investigation</button>
                        <p class="hint">Runs against the selected target in the signed lab scope.</p>
                    </div>
                </form>
              </div>
            </div>
        </section>

        <div class="run-toolbar">
            <div><label class="small-label" for="run-select">Investigation</label><select id="run-select" class="field" aria-describedby="message"></select></div>
            <span class="badge" id="run-status">Loading</span>
        </div>
        <div id="message" role="status" aria-live="polite"></div>
        <div id="content" aria-busy="true">
            <div class="sk-stats" aria-hidden="true">@for ($i = 0; $i < 4; $i++)<div><span class="skeleton" style="width:56px;height:34px"></span><span class="skeleton" style="width:96px;height:12px"></span></div>@endfor</div>
            <div class="sk-rows" aria-hidden="true">@for ($i = 0; $i < 4; $i++)<span class="skeleton" style="height:56px"></span>@endfor</div>
        </div>

        <dialog id="detail" aria-labelledby="detail-eyebrow">
            <div class="dialog-top"><span class="eyebrow" id="detail-eyebrow">Finding details</span><button id="close-detail" class="icon-btn" type="button" aria-label="Close details"><svg class="icon" aria-hidden="true"><use href="#i-close"/></svg></button></div>
            <div id="detail-content"></div>
        </dialog>
    </div>

    <x-slot name="scripts">
        @vite('resources/js/workspace.js')
    </x-slot>
</x-app-layout>
