@php
    $owner = match ($toolLog->loggable_type) {
        \App\Models\SecurityScanner::class => 'SecurityScanner',
        \App\Models\LogAnalyzer::class => 'LogAnalyzer',
        \App\Models\KnowledgeSource::class => 'KnowledgeSource',
        \App\Models\MalwareScanner::class => 'MalwareScanner',
        default => class_basename($toolLog->loggable_type),
    };
    $in = $toolLog->input_parameters ?? [];
    $out = $toolLog->output_payload ?? [];
    $failed = $toolLog->status !== 'success';
    $headline = match ($toolLog->tool_name) {
        'run_investigation' => trim(str_replace('_', ' ', $in['skill'] ?? '').(isset($in['target']) ? ' · '.$in['target'] : ''))
            .(isset($out['run_id']) ? ' · '.count($out['findings'] ?? []).' findings' : ''),
        'lookup_cve' => ($in['cve_id'] ?? '').(isset($out['cvss_score']) ? ' · CVSS '.$out['cvss_score'].' '.strtolower($out['severity'] ?? '') : '')
            .(! empty($out['known_exploited']) ? ' · exploited in the wild' : ''),
        'search_cves' => '“'.($in['keyword'] ?? '').'”'.(isset($out['count']) ? ' · '.$out['count'].' results' : ''),
        'get_investigation' => $in['run_id'] ?? '',
        'list_investigations' => isset($out['count']) ? $out['count'].' recorded runs' : '',
        default => '',
    };
@endphp
<details class="step">
    <summary>
        <span class="step-dot {{ $failed ? 'failed' : '' }}" title="{{ $toolLog->status }}"></span>
        <span class="step-tool">{{ $toolLog->tool_name }}</span>
        <span class="step-headline">{{ $headline }}</span>
        <span class="step-owner" title="Polymorphic owner: {{ $toolLog->loggable_type }} #{{ $toolLog->loggable_id }}">{{ $owner }}: {{ $toolLog->loggable?->name ?? 'unknown' }}</span>
        <span class="step-time">{{ number_format($toolLog->execution_time_ms) }} ms</span>
    </summary>
    <div class="step-body">
        <pre aria-label="input_parameters">input_parameters {{ json_encode($in, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
        <pre aria-label="output_payload">output_payload {{ json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
    </div>
</details>
@if ($failed && isset($out['error']))
    <p class="step-error">{{ $out['error'] }}</p>
@endif
@if ($toolLog->tool_name === 'run_investigation' && isset($out['run_id']))
    <div class="step-findings">
        @foreach (array_slice($out['findings'] ?? [], 0, 5) as $finding)
            <div><span class="severity-dot {{ $finding['severity'] ?? 'info' }}"></span><span class="severity {{ $finding['severity'] ?? 'info' }}">{{ $finding['severity'] ?? '' }}</span> {{ $finding['title'] ?? '' }} <span class="hint">({{ $finding['status'] ?? '' }})</span></div>
        @endforeach
        <div><a class="step-link" href="{{ route('investigations.index', ['run' => $out['run_id'], 'view' => 'overview']) }}">Open full report in workspace ↗</a>
            @if (! empty($out['planner_note']))<span class="hint">· planner: {{ $out['planner'] }} (LLM plan did not finish)</span>@endif
        </div>
    </div>
@elseif ($toolLog->tool_name === 'lookup_cve' && isset($out['nvd_url']))
    <div class="step-findings"><div><a class="step-link" href="{{ $out['nvd_url'] }}" rel="noreferrer noopener" target="_blank">{{ $out['id'] }} on NVD ↗</a></div></div>
@endif
