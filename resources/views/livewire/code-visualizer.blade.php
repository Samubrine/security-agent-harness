@php
    $lines = explode("\n", $code);
@endphp

<aside class="code-visualizer-panel" aria-label="Code and Tool Visualizer">
    {{-- Top Section: Live Tool Status & Server Polling (Slide 20, 21, 36) --}}
    <section class="visualizer-tool-monitor" wire:poll.2s="pollToolStatus">
        <div class="monitor-header">
            <div class="monitor-status-row">
                <span 
                    class="monitor-status-dot {{ $toolStatus === 'MEMINDAI' ? 'dot-polling animate-pulse' : ($toolStatus === 'SUKSES' ? 'dot-success' : ($toolStatus === 'GAGAL' ? 'dot-failed' : 'dot-standby')) }}" 
                    aria-hidden="true"
                ></span>
                <span class="monitor-label">Eksekusi Tools:</span>
                <strong class="monitor-badge {{ $toolStatus === 'SUKSES' ? 'badge-ok' : ($toolStatus === 'GAGAL' ? 'badge-bad' : 'badge-idle') }}">
                    {{ $toolStatus }}
                </strong>
            </div>
            <time class="monitor-time" title="Sinkronisasi server tiap 2 detik">
                {{ $lastCheckedTime ?: now()->format('H:i:s') }}
            </time>
        </div>

        <div class="monitor-active-tool">
            <span class="eyebrow" style="font-size:10px;">Tool Aktif</span>
            <div class="tool-active-name" title="{{ $activeToolName }}">
                {{ $activeToolName }}
            </div>
        </div>

        {{-- Dynamic Progress Bar --}}
        <div class="progress-bar-container" role="progressbar" aria-valuenow="{{ $progressPercent }}" aria-valuemin="0" aria-valuemax="100">
            <div class="progress-bar-fill" style="width: {{ $progressPercent }}%;"></div>
        </div>
    </section>

    {{-- Middle Section: Split-Panel Monospaced Code Visualizer & Sandbox Runner --}}
    <section class="visualizer-editor-container" x-data="{ copied: false }">
        {{-- Preset Demo Tabs --}}
        <div class="editor-preset-bar">
            <span class="preset-label">Presets:</span>
            <button type="button" wire:click="loadPreset('python')" class="preset-tab {{ $language === 'python' ? 'is-active' : '' }}">Scanner.py</button>
            <button type="button" wire:click="loadPreset('bash')" class="preset-tab {{ $language === 'bash' ? 'is-active' : '' }}">Patch.sh</button>
            <button type="button" wire:click="loadPreset('json')" class="preset-tab {{ $language === 'json' ? 'is-active' : '' }}">Report.json</button>
        </div>

        <div class="editor-titlebar">
            <div class="editor-file-tab">
                <svg class="icon icon-code" aria-hidden="true" style="width:13px;height:13px;"><use href="#i-chevron"/></svg>
                <span class="file-name">{{ $filename }}</span>
                <span class="lang-tag">{{ strtoupper($language) }}</span>
            </div>
            <div class="editor-actions">
                <button 
                    type="button" 
                    wire:click="executeCode" 
                    wire:loading.attr="disabled" 
                    class="action-pill-btn run-btn"
                    title="Jalankan skrip di sandbox container"
                >
                    <span wire:loading.remove wire:target="executeCode">▶ Run Script</span>
                    <span wire:loading wire:target="executeCode" class="inline-spinner-wrap">
                        <span class="inline-spinner" aria-hidden="true"></span> Running...
                    </span>
                </button>
                <button 
                    type="button" 
                    class="action-pill-btn copy-btn" 
                    @click="navigator.clipboard.writeText($refs.codeContent.innerText); copied = true; setTimeout(() => copied = false, 2000)"
                    :title="copied ? 'Tersalin ke clipboard!' : 'Salin kode'"
                >
                    <span x-show="!copied">Copy</span>
                    <span x-show="copied" x-cloak class="copied-feedback">✓ Copied</span>
                </button>
            </div>
        </div>

        {{-- Monospaced Code Body with Line Numbers Gutter --}}
        <div class="editor-body">
            <div class="editor-gutter" aria-hidden="true">
                @foreach ($lines as $index => $l)
                    <span class="line-num">{{ $index + 1 }}</span>
                @endforeach
            </div>
            <pre class="editor-code"><code x-ref="codeContent" class="language-{{ $language }}">{{ $code }}</code></pre>
        </div>

        {{-- Collapsible Execution Output Console Drawer --}}
        @if ($executionOutput)
            <div class="execution-terminal-drawer">
                <div class="terminal-header">
                    <div class="terminal-title">
                        <span class="terminal-dot" aria-hidden="true"></span>
                        <span>Console Output · Sandbox Execution</span>
                    </div>
                    <button type="button" wire:click="$set('executionOutput', null)" class="terminal-close" title="Clear console">✕</button>
                </div>
                <pre class="terminal-output">{{ $executionOutput }}</pre>
            </div>
        @endif

        <div class="editor-footer">
            <span class="editor-stat">{{ count($lines) }} lines</span>
            <span class="editor-encoding">UTF-8</span>
            <span wire:loading wire:target="executeCode" class="editor-loading-flag">Executing Sandbox...</span>
        </div>
    </section>

    {{-- Bottom Section: Recent Tool Audit Log Timeline --}}
    @if (!empty($recentLogs))
        <section class="visualizer-recent-logs">
            <div class="logs-header">
                <span class="eyebrow" style="font-size:10px;">Log Audit Terbaru</span>
                <span class="logs-count">{{ count($recentLogs) }}</span>
            </div>
            <div class="logs-list">
                @foreach ($recentLogs as $log)
                    <div class="log-row" wire:key="recent-log-{{ $log['id'] }}">
                        <span class="log-indicator {{ $log['status'] === 'success' ? 'is-success' : 'is-failed' }}" aria-hidden="true"></span>
                        <div class="log-details">
                            <span class="log-name">{{ $log['name'] }}</span>
                            <span class="log-meta">{{ $log['time'] }} · {{ $log['duration'] }}ms</span>
                        </div>
                    </div>
                @endforeach
            </div>
        </section>
    @endif
</aside>
