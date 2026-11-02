@php
    $owner = match ($toolLog->loggable_type) {
        \App\Models\SecurityScanner::class => ['🛡️', 'SecurityScanner', 'bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300 border-blue-200 dark:border-blue-800'],
        \App\Models\LogAnalyzer::class => ['📜', 'LogAnalyzer', 'bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300 border-amber-200 dark:border-amber-800'],
        \App\Models\KnowledgeSource::class => ['📚', 'KnowledgeSource', 'bg-teal-100 text-teal-800 dark:bg-teal-900/50 dark:text-teal-300 border-teal-200 dark:border-teal-800'],
        default => ['🦠', 'MalwareScanner', 'bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300 border-rose-200 dark:border-rose-800'],
    };
    $in = $toolLog->input_parameters ?? [];
    $out = $toolLog->output_payload ?? [];
    $headline = match ($toolLog->tool_name) {
        'run_investigation' => ($in['skill'] ?? '').(isset($in['target']) ? ' → '.$in['target'] : '')
            .(isset($out['run_id']) ? ' · '.count($out['findings'] ?? []).' findings · '.$out['run_id'] : ''),
        'lookup_cve' => ($in['cve_id'] ?? '').(isset($out['cvss_score']) ? ' · CVSS '.$out['cvss_score'].' '.($out['severity'] ?? '') : '')
            .(! empty($out['known_exploited']) ? ' · exploited in the wild' : ''),
        'search_cves' => '"'.($in['keyword'] ?? '').'"'.(isset($out['count']) ? ' · '.$out['count'].' results' : ''),
        'get_investigation' => $in['run_id'] ?? '',
        'list_investigations' => isset($out['count']) ? $out['count'].' runs' : '',
        default => '',
    };
@endphp
<div x-data="{ showDetails: false }" class="rounded-xl border border-gray-200 dark:border-gray-700/80 bg-gray-50/75 dark:bg-gray-900/50 p-3 space-y-2">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div class="flex items-center gap-2 flex-wrap min-w-0">
            <span class="text-[11px] font-bold text-gray-400 font-mono">#{{ $index + 1 }}</span>
            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-bold border {{ $owner[2] }}" title="Polymorphic owner: {{ $toolLog->loggable_type }} #{{ $toolLog->loggable_id }}">
                {{ $owner[0] }} {{ $owner[1] }}: {{ $toolLog->loggable?->name ?? 'unknown' }}
            </span>
            <span class="font-mono text-xs font-semibold text-gray-800 dark:text-gray-200">{{ $toolLog->tool_name }}</span>
            <span class="text-xs text-gray-500 dark:text-gray-400 truncate">{{ $headline }}</span>
        </div>
        <div class="flex items-center gap-2 text-xs shrink-0">
            <span class="font-mono text-gray-500 dark:text-gray-400">⏱️ {{ number_format($toolLog->execution_time_ms) }} ms</span>
            <span class="px-2 py-0.5 rounded text-[11px] font-bold uppercase {{ $toolLog->status === 'success' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300' : 'bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300' }}">
                {{ $toolLog->status }}
            </span>
            <button type="button" @click="showDetails = !showDetails" class="text-indigo-600 dark:text-indigo-400 font-semibold hover:underline">
                <span x-text="showDetails ? 'Tutup' : 'Payload'"></span>
            </button>
        </div>
    </div>
    @if($toolLog->status !== 'success' && isset($out['error']))
        <p class="text-xs text-rose-600 dark:text-rose-400">{{ $out['error'] }}</p>
    @endif
    <div x-show="showDetails" x-cloak class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-xs font-mono">
        <div class="p-2.5 rounded-lg bg-gray-900 text-gray-200 border border-gray-800 min-w-0">
            <span class="text-gray-400 font-bold block mb-1">input_parameters</span>
            <pre class="overflow-x-auto text-[11px] text-sky-300">{{ json_encode($in, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
        </div>
        <div class="p-2.5 rounded-lg bg-gray-900 text-gray-200 border border-gray-800 min-w-0">
            <span class="text-gray-400 font-bold block mb-1">output_payload</span>
            <pre class="overflow-x-auto max-h-96 text-[11px] text-emerald-300">{{ json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
        </div>
    </div>
</div>
