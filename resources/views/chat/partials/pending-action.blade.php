@php
    $resolved = $action['resolved'] ?? null;
    $skill = str_replace('_', ' ', (string) ($action['skill'] ?? 'investigation'));
@endphp
@if ($resolved !== null)
    <p class="action-resolved">
        @if (($action['type'] ?? '') === 'approval')
            {{ $resolved === 'approve' ? '✓ You approved this step.' : '✗ You declined this step.' }}
        @else
            ✓ You chose <code>{{ $resolved }}</code>.
        @endif
    </p>
@elseif (! $isLatest)
    <p class="action-resolved">This question was not answered.</p>
@elseif (($action['type'] ?? '') === 'approval')
    <div class="action-card">
        <div class="steps-title"><span><svg class="icon" aria-hidden="true" style="width:14px;height:14px;vertical-align:-2px"><use href="#i-warn"/></svg> Approval needed</span><span>policy verdict: ask</span></div>
        <div class="action-body">
            <p>The harness skipped {{ count($action['requests'] ?? []) === 1 ? 'one step' : count($action['requests']).' steps' }} of the {{ $skill }}{{ ! empty($action['target']) ? ' on '.$action['target'] : '' }} because a person has to approve {{ count($action['requests'] ?? []) === 1 ? 'it' : 'them' }} first:</p>
            <ul>
                @foreach ($action['requests'] ?? [] as $request)
                    <li><strong>{{ $request['provider'] }}</strong> for <code>{{ $request['capability'] }}</code>: {{ $request['reason'] }}.</li>
                @endforeach
            </ul>
            <div class="action-buttons">
                <form method="POST" action="{{ route('chat.resolve', [$message->chat_session_id, $message->id]) }}" @submit.prevent="run($el)">
                    @csrf
                    <input type="hidden" name="decision" value="approve">
                    <button class="button primary" type="submit" :disabled="busy" :class="{ 'is-loading': busy }"><span>Approve and run again</span></button>
                </form>
                <form method="POST" action="{{ route('chat.resolve', [$message->chat_session_id, $message->id]) }}" @submit.prevent="run($el)">
                    @csrf
                    <input type="hidden" name="decision" value="decline">
                    <button class="button" type="submit" :disabled="busy" :class="{ 'is-loading': busy }"><span>Decline</span></button>
                </form>
            </div>
            <p class="hint">Approving answers “yes” to exactly these requests for one rerun. Anything new the rerun asks for is still declined.</p>
        </div>
    </div>
@elseif (($action['type'] ?? '') === 'context')
    @php $field = $action['fields'][0] ?? ['name' => 'target', 'label' => 'Which target?', 'options' => []]; @endphp
    <div class="action-card is-context">
        <div class="steps-title"><span>One detail needed</span><span>{{ $skill }}</span></div>
        <form class="action-body" method="POST" action="{{ route('chat.resolve', [$message->chat_session_id, $message->id]) }}" @submit.prevent="run($el)">
            @csrf
            <label class="small-label field-label" for="ctx-{{ $message->id }}">{{ $field['label'] }}</label>
            <div class="action-buttons">
                <select class="field" id="ctx-{{ $message->id }}" name="{{ $field['name'] }}" style="max-width:260px">
                    @foreach ($field['options'] as $option)
                        <option value="{{ $option }}">{{ $option }}</option>
                    @endforeach
                </select>
                <button class="button primary" type="submit" :disabled="busy" :class="{ 'is-loading': busy }"><span>Continue</span></button>
            </div>
            <p class="hint">Options come from the signed scope, so only authorised targets can be chosen.</p>
        </form>
    </div>
@endif
