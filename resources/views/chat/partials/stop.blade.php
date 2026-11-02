@use('App\Support\Plain')
@php
    $owner = match ($toolLog->loggable_type) {
        \App\Models\SecurityScanner::class => 'SecurityScanner',
        \App\Models\LogAnalyzer::class => 'LogAnalyzer',
        \App\Models\KnowledgeSource::class => 'KnowledgeSource',
        \App\Models\MalwareScanner::class => 'MalwareScanner',
        default => class_basename((string) $toolLog->loggable_type),
    };
    $in = $toolLog->input_parameters ?? [];
    $out = $toolLog->output_payload ?? [];
    $failed = $toolLog->status !== 'success';
    $reason = Plain::toolReason($toolLog);
@endphp
<li class="stop">
    <span class="node {{ $failed ? 'failed' : '' }}" aria-hidden="true">{{ $failed ? '!' : $number }}</span>
    <div>
        <h4>{{ Plain::toolTitle($toolLog) }}</h4>
        @if ($reason)<p class="why">{{ $reason }}</p>@endif
        <div class="outcome">
            <span class="pill {{ $failed ? 'critical' : 'ok' }}">{{ $failed ? 'Stopped' : 'Done' }}</span>
            <span>{{ Plain::toolOutcome($toolLog) }}</span>
            <span class="took">{{ number_format($toolLog->execution_time_ms / 1000, 1) }} s</span>
        </div>

        @if ($toolLog->tool_name === 'run_investigation' && isset($out['run_id']))
            <div class="found">
                @foreach (array_slice($out['findings'] ?? [], 0, 5) as $finding)
                    <div>
                        <span class="pill {{ $finding['severity'] ?? 'info' }}">{{ Plain::severity($finding['severity'] ?? null)[0] }}</span>
                        <span title="{{ $finding['title'] ?? '' }}">{{ Plain::findingTitle($finding['title'] ?? '') }}</span>
                        <small>{{ Plain::status($finding['status'] ?? null) }}</small>
                    </div>
                @endforeach
            </div>
            <a class="step-link" style="text-decoration:underline" href="{{ route('investigations.index', ['run' => $out['run_id'], 'view' => 'overview']) }}">Open the full report</a>
        @elseif ($toolLog->tool_name === 'lookup_cve' && isset($out['nvd_url']))
            <a class="step-link" style="text-decoration:underline" href="{{ $out['nvd_url'] }}" rel="noreferrer noopener" target="_blank">Read {{ $out['id'] }} on the NIST site</a>
        @endif

        <details class="tech">
            <summary>Technical details</summary>
            <span class="owner">Logged as <code>{{ $toolLog->tool_name }}</code> on {{ $owner }}: {{ $toolLog->loggable?->name ?? 'unknown' }} (polymorphic <code>{{ $toolLog->loggable_type }}</code> #{{ $toolLog->loggable_id }})</span>
            <pre aria-label="input_parameters">input_parameters {{ json_encode($in, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
            <pre aria-label="output_payload">output_payload {{ json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
        </details>
    </div>
</li>
