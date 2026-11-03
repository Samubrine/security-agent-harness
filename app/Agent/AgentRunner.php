<?php

namespace App\Agent;

use App\Agent\Tools\NeedsContext;
use App\Agent\Tools\ToolException;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\EvidenceArtifact;
use App\Models\ToolExecutionLog;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

/**
 * The agent loop.
 *
 *   user message -> LLM -> (tool calls -> execute -> results back to LLM)* -> final answer
 *
 * The LLM decides which tools to call and when it has enough to answer. Laravel validates and
 * executes every call, records it as a polymorphic ToolExecutionLog on the assistant message,
 * and enforces a hard step limit so a confused model cannot loop forever.
 */
class AgentRunner
{
    /** Tool output larger than this is truncated before it is shown to the model. */
    private const MAX_TOOL_RESULT_CHARS = 6000;

    /** Long strings in tool output are shortened for the model; the full output stays in the log. */
    private const MAX_TOOL_STRING_CHARS = 500;

    /** Keys that cost many tokens and add nothing the model needs to answer. */
    private const MODEL_HIDDEN_KEYS = ['references', 'more_evidence', 'explanation', 'cvss_vector'];

    private const MAX_CALLS_PER_STEP = 4;

    public function __construct(
        private readonly LlmClient $llm,
        private readonly ToolRegistry $tools,
        private readonly SystemPrompt $systemPrompt,
        private readonly int $maxSteps = 6,
        private readonly int $historyMessages = 12,
        private readonly string $toolMode = 'auto',
        private readonly ?Progress $progress = null,
        private readonly ?ClaimChecker $claims = null,
    ) {}

    /** Set when a tool asks the operator for missing context; ends the turn. */
    private ?NeedsContext $contextRequest = null;

    /**
     * Produce the assistant's reply to the latest user message in the session.
     *
     * @param  (callable(array<string, mixed>): void)|null  $onEvent  receives live progress events
     */
    public function respond(ChatSession $session, ?callable $onEvent = null): ChatMessage
    {
        $this->progress?->listen($onEvent);
        try {
            return $this->turn($session);
        } finally {
            $this->progress?->listen(null);
        }
    }

    private function turn(ChatSession $session): ChatMessage
    {
        $this->contextRequest = null;
        $history = $session->chatMessages()
            ->with('toolExecutionLogs')
            ->orderByDesc('sequence_number')
            ->limit($this->historyMessages)
            ->get()
            ->reverse()
            ->values();

        $assistant = ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'assistant',
            'content' => '…',
            'token_count' => 0,
            'sequence_number' => (int) $session->chatMessages()->max('sequence_number') + 1,
        ]);

        $textMode = $this->toolMode === 'json';
        $reasoning = [];
        $completionTokens = 0;

        try {
            $messages = $this->initialMessages($session, $history, $textMode);
            $answer = null;

            for ($step = 1; $step <= $this->maxSteps; $step++) {
                $this->emit(['type' => 'thinking', 'label' => $step === 1 ? 'Reading your question and deciding what to do' : 'Reading the results and deciding the next step']);
                $reply = $this->call($messages, $textMode);
                $completionTokens += $reply->completionTokens;
                if ($reply->reasoning) {
                    $reasoning[] = "**Step {$step}**\n".$reply->reasoning;
                }

                if (! $reply->wantsTools()) {
                    $answer = $reply->content;
                    break;
                }

                $calls = array_slice($reply->toolCalls, 0, self::MAX_CALLS_PER_STEP);
                $messages[] = $this->assistantToolMessage($reply, $calls, $textMode);
                foreach ($calls as $call) {
                    $result = $this->executeTool($assistant, $call);
                    $messages[] = $this->toolResultMessage($call, $result, $textMode);
                    if ($this->contextRequest !== null) {
                        break 2;
                    }
                }
            }

            if ($this->contextRequest !== null) {
                // Missing context is answered by the operator, not guessed by the model.
                $answer = 'Before I can run the **'.str_replace('_', ' ', $this->contextRequest->skill).'** I need one detail from you: '
                    .lcfirst($this->contextRequest->fields[0]['label'] ?? 'which target?').' Pick it below.';
            } elseif ($answer === null || $answer === '') {
                // Out of steps (or an empty reply): ask for an answer from what is already known.
                $this->emit(['type' => 'thinking', 'label' => 'Out of steps: writing the answer from what it has']);
                $messages[] = ['role' => 'user', 'content' => 'You have no tool calls left. Write the final answer now, using only the tool results above, and say what is still unknown.'];
                $reply = $this->llm->chat($messages);
                $completionTokens += $reply->completionTokens;
                if ($reply->reasoning) {
                    $reasoning[] = '**Final**'."\n".$reply->reasoning;
                }
                $answer = $reply->content ?: 'I could not produce an answer from the tool results. Please rephrase or ask a narrower question.';
            }
        } catch (LlmException $e) {
            Log::warning('Agent LLM call failed', ['session' => $session->id, 'error' => $e->getMessage()]);
            $answer = "⚠️ **The language model could not be reached.**\n\n".$e->getMessage();
        }

        $this->emit(['type' => 'thinking', 'label' => 'Checking the answer against the evidence']);
        $assistant->update([
            'content' => $answer,
            'reasoning' => $reasoning ? implode("\n\n", $reasoning) : null,
            'token_count' => $completionTokens ?: (int) ceil(mb_strlen($answer) / 4),
            'pending_action' => $this->pendingAction($assistant),
            'claim_check' => $this->claims?->check($answer, EvidenceArtifact::where('chat_session_id', $session->id)->get()),
        ]);
        $this->emit(['type' => 'answer', 'message' => $assistant->id]);

        return $assistant->load('toolExecutionLogs.loggable');
    }

    /**
     * What the operator must answer before the agent can go on, if anything: missing context, or
     * an approval the harness asked for in this turn's last investigation.
     *
     * @return array<string, mixed>|null
     */
    private function pendingAction(ChatMessage $assistant): ?array
    {
        if ($this->contextRequest !== null) {
            return [
                'type' => 'context',
                'skill' => $this->contextRequest->skill,
                'objective' => $this->contextRequest->objective,
                'fields' => $this->contextRequest->fields,
            ];
        }

        $run = $assistant->toolExecutionLogs()
            ->where('tool_name', 'run_investigation')
            ->where('status', 'success')
            ->latest('id')
            ->first();
        $needed = $run?->output_payload['approval_needed'] ?? [];
        if ($needed === []) {
            return null;
        }

        return [
            'type' => 'approval',
            'skill' => $run->input_parameters['skill'] ?? null,
            'target' => $run->output_payload['target'] ?? ($run->input_parameters['target'] ?? null),
            'objective' => $run->input_parameters['objective'] ?? null,
            'run_id' => $run->output_payload['run_id'] ?? null,
            'requests' => array_map(fn ($r) => [
                'provider' => $r['provider'] ?? '',
                'capability' => $r['capability'] ?? '',
                'reason' => $r['reason'] ?? '',
            ], $needed),
        ];
    }

    /**
     * @param  array<string, mixed>  $event
     */
    private function emit(array $event): void
    {
        $this->progress?->emit($event);
    }

    /**
     * One LLM turn. In "auto" mode a gateway that rejects the `tools` parameter switches the rest
     * of this response to text tool calls.
     *
     * @param  list<array<string, mixed>>  $messages
     */
    private function call(array &$messages, bool &$textMode): LlmReply
    {
        if ($textMode) {
            return $this->llm->chat($messages);
        }

        try {
            return $this->llm->chat($messages, $this->tools->schemas());
        } catch (LlmException $e) {
            if ($this->toolMode !== 'auto' || ! in_array($e->getCode(), [400, 422, 501], true)) {
                throw $e;
            }
            $textMode = true;
            $messages[0]['content'] .= "\n\n".$this->systemPrompt->toolSection($this->tools);

            return $this->llm->chat($messages);
        }
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function initialMessages(ChatSession $session, iterable $history, bool $textMode): array
    {
        $messages = [[
            'role' => 'system',
            'content' => $this->systemPrompt->build($session->agent_mode, $this->tools, $textMode),
        ]];

        foreach ($history as $message) {
            if ($message->role === 'system') {
                continue;
            }
            $content = $message->content;
            if ($message->role === 'assistant' && $message->toolExecutionLogs->isNotEmpty()) {
                // Let follow-up questions refer to earlier runs without re-running them.
                $used = $message->toolExecutionLogs->map(fn (ToolExecutionLog $log) => $this->describeLog($log))->implode('; ');
                $content .= "\n\n[Tools used in this turn: {$used}]";
            }
            $messages[] = ['role' => $message->role, 'content' => $content];
        }

        return $messages;
    }

    /**
     * @param  list<ToolCall>  $calls
     * @return array<string, mixed>
     */
    private function assistantToolMessage(LlmReply $reply, array $calls, bool $textMode): array
    {
        if ($textMode) {
            $text = collect($calls)->map(fn (ToolCall $c) => '<tool_call>'.json_encode(['name' => $c->name, 'arguments' => $c->arguments], JSON_UNESCAPED_SLASHES).'</tool_call>')->implode("\n");

            return ['role' => 'assistant', 'content' => trim($reply->content."\n".$text)];
        }

        return [
            'role' => 'assistant',
            'content' => $reply->content !== '' ? $reply->content : null,
            'tool_calls' => array_map(fn (ToolCall $c) => [
                'id' => $c->id,
                'type' => 'function',
                'function' => ['name' => $c->name, 'arguments' => json_encode((object) $c->arguments, JSON_UNESCAPED_SLASHES)],
            ], $calls),
        ];
    }

    /**
     * @param  array<string, mixed>  $result
     * @return array<string, mixed>
     */
    private function toolResultMessage(ToolCall $call, array $result, bool $textMode): array
    {
        $json = json_encode($this->compactForModel($result), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: '{}';
        if (strlen($json) > self::MAX_TOOL_RESULT_CHARS) {
            $json = substr($json, 0, self::MAX_TOOL_RESULT_CHARS).'… [truncated]';
        }

        if ($textMode) {
            return ['role' => 'user', 'content' => "<tool_response name=\"{$call->name}\">\n{$json}\n</tool_response>"];
        }

        return ['role' => 'tool', 'tool_call_id' => $call->id, 'content' => $json];
    }

    /**
     * Free-tier gateways allow only a few thousand tokens per minute, so the model gets a trimmed
     * copy of each tool result: no reference lists, short strings, at most 3 evidence lines per
     * finding. The ToolExecutionLog and the workspace keep the full output.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function compactForModel(array $data, ?string $key = null): array
    {
        $out = [];
        foreach ($data as $k => $value) {
            if (is_string($k) && in_array($k, self::MODEL_HIDDEN_KEYS, true)) {
                continue;
            }
            if (is_array($value)) {
                $value = $this->compactForModel($value, is_string($k) ? $k : $key);
                if (($k === 'evidence') && array_is_list($value)) {
                    $value = array_slice($value, 0, 3);
                }
            } elseif (is_string($value)) {
                $value = Str::limit($value, self::MAX_TOOL_STRING_CHARS);
            }
            $out[$k] = $value;
        }

        return $out;
    }

    /**
     * Run one tool call and record it. Failures are returned to the model as data so it can
     * correct itself (e.g. pick a valid target) instead of crashing the whole reply. A successful
     * result is also stored as a content-addressed evidence artifact.
     *
     * @return array<string, mixed>
     */
    private function executeTool(ChatMessage $assistant, ToolCall $call): array
    {
        $tool = $this->tools->get($call->name);
        if ($tool === null) {
            return ['error' => "Unknown tool `{$call->name}`. Available: ".implode(', ', $this->tools->names()).'.'];
        }

        $this->emit(['type' => 'tool_started', 'tool' => $call->name, 'label' => $this->startedLabel($call)]);
        $started = microtime(true);
        try {
            $result = $tool->execute($call->arguments);
            $status = 'success';
        } catch (NeedsContext $e) {
            $this->contextRequest = $e;
            $result = ['needs_context' => $e->fields, 'error' => $e->getMessage()];
            $status = 'failed';
        } catch (ToolException $e) {
            $result = ['error' => $e->getMessage()];
            $status = 'failed';
        } catch (Throwable $e) {
            report($e);
            $result = ['error' => 'The tool crashed: '.Str::limit($e->getMessage(), 300)];
            $status = 'failed';
        }
        $elapsed = (int) round((microtime(true) - $started) * 1000);

        $owner = $tool->loggable($call->arguments);
        $log = ToolExecutionLog::create([
            'chat_message_id' => $assistant->id,
            'tool_name' => $call->name,
            'status' => $status,
            'input_parameters' => $call->arguments,
            'output_payload' => $result,
            'execution_time_ms' => $elapsed,
            'loggable_type' => $owner::class,
            'loggable_id' => $owner->getKey(),
        ]);

        if ($status === 'success') {
            EvidenceArtifact::create([
                'chat_session_id' => $assistant->chat_session_id,
                'tool_execution_log_id' => $log->id,
                'kind' => $call->name,
                'source' => $this->evidenceSource($call, $result),
                'sha256' => hash('sha256', EvidenceArtifact::canonicalJson($result)),
                'content' => $result,
            ]);
        }

        $this->emit(['type' => 'tool_finished', 'tool' => $call->name, 'ok' => $status === 'success', 'label' => $this->finishedLabel($call, $result, $status)]);

        return $result;
    }

    /**
     * @param  array<string, mixed>  $result
     */
    private function evidenceSource(ToolCall $call, array $result): string
    {
        return match ($call->name) {
            'run_investigation', 'get_investigation' => 'harness:'.($result['run_id'] ?? 'unknown'),
            'lookup_cve' => (string) ($result['nvd_url'] ?? 'nvd'),
            'search_cves' => 'nvd:search:'.($result['keyword'] ?? ''),
            'list_investigations' => 'harness:archive',
            default => 'tool:'.$call->name,
        };
    }

    private function startedLabel(ToolCall $call): string
    {
        $a = $call->arguments;

        return match ($call->name) {
            'run_investigation' => 'Running the '.str_replace('_', ' ', (string) ($a['skill'] ?? 'investigation')).(isset($a['target']) ? ' on '.$a['target'] : ''),
            'lookup_cve' => 'Looking up '.($a['cve_id'] ?? 'a CVE').' in the NIST vulnerability database',
            'search_cves' => 'Searching the NIST database for "'.($a['keyword'] ?? '').'"',
            'list_investigations' => 'Checking earlier investigations',
            'get_investigation' => 'Re-reading investigation '.($a['run_id'] ?? ''),
            default => 'Using '.$call->name,
        };
    }

    /**
     * @param  array<string, mixed>  $result
     */
    private function finishedLabel(ToolCall $call, array $result, string $status): string
    {
        if (isset($result['needs_context'])) {
            return 'Needs one detail from you first';
        }
        if ($status !== 'success') {
            return 'Did not run: '.Str::limit((string) ($result['error'] ?? 'failed'), 140);
        }

        return match ($call->name) {
            'run_investigation' => count($result['findings'] ?? []).' findings'
                .(($c = collect($result['cross_checks'] ?? [])->where('relation', 'conflict')->count()) ? ", {$c} source conflict(s)" : '')
                .(($result['approval_needed'] ?? []) !== [] ? ', a step is waiting for your approval' : ''),
            'lookup_cve' => isset($result['cvss_score']) ? 'CVSS '.$result['cvss_score'].' '.strtolower((string) ($result['severity'] ?? '')).(! empty($result['known_exploited']) ? ', exploited in the wild' : '') : 'no details found',
            'search_cves' => ($result['count'] ?? 0).' results',
            'list_investigations' => ($result['count'] ?? 0).' recorded runs',
            default => 'done',
        };
    }

    private function describeLog(ToolExecutionLog $log): string
    {
        $in = $log->input_parameters ?? [];
        $out = $log->output_payload ?? [];
        $detail = match ($log->tool_name) {
            'run_investigation' => ($in['skill'] ?? '?').(isset($in['target']) ? ' on '.$in['target'] : '').' -> '.($out['run_id'] ?? 'failed')
                .', '.count($out['findings'] ?? []).' findings',
            'lookup_cve' => $in['cve_id'] ?? '?',
            'search_cves' => '"'.($in['keyword'] ?? '').'"',
            'get_investigation' => $in['run_id'] ?? '?',
            default => '',
        };

        return trim($log->tool_name.' '.$detail).($log->status === 'failed' ? ' (failed)' : '');
    }
}
