@if (is_array($check) && ($check['checked'] ?? 0) > 0)
    @php $issues = $check['issues'] ?? []; @endphp
    <div class="fact-check {{ $issues ? 'warn' : 'ok' }}">
        @if ($issues === [])
            <strong>✓ Fact check:</strong> all {{ $check['checked'] }} checkable {{ \Illuminate\Support\Str::plural('fact', $check['checked']) }} in this answer (CVE ids, CVSS scores, run ids, exploitation claims) match the evidence from {{ $check['artifacts'] }} tool {{ \Illuminate\Support\Str::plural('result', $check['artifacts']) }}.
        @else
            <strong>⚠ Fact check:</strong> {{ $check['supported'] }} of {{ $check['checked'] }} checkable facts match the evidence. Not supported:
            <ul>
                @foreach ($issues as $issue)
                    <li><code>{{ $issue['claim'] }}</code>: {{ $issue['problem'] }}</li>
                @endforeach
            </ul>
        @endif
    </div>
@endif
