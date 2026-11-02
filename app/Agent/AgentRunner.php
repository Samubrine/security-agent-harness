<?php

namespace App\Agent;

use App\Agent\Tools\ToolException;
use App\Models\ChatMessage;
use App\Models\ChatSession;
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
    ) {}

    /**
     * Produce the assistant's reply to the latest user message in the session.
     */
    public function respond(ChatSession $session): ChatMessage
    {
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
                // The sentence the model wrote next to its tool call is its stated reason; keep it.
                $why = trim($reply->content) !== '' ? Str::limit(trim($reply->content), 400) : null;
                foreach ($calls as $call) {
                    $result = $this->executeTool($assistant, $call, $why);
                    $messages[] = $this->toolResultMessage($call, $result, $textMode);
                }
            }

            if ($answer === null || $answer === '') {
                // Out of steps (or an empty reply): ask for an answer from what is already known.
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

        [$answer, $suggestions] = $this->extractSuggestions($answer);

        $assistant->update([
            'content' => $answer,
            'suggestions' => $suggestions ?: null,
            'reasoning' => $reasoning ? implode("\n\n", $reasoning) : null,
            'token_count' => $completionTokens ?: (int) ceil(mb_strlen($answer) / 4),
        ]);

        return $assistant->load('toolExecutionLogs.loggable');
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
     * correct itself (e.g. pick a valid target) instead of crashing the whole reply.
     *
     * @return array<string, mixed>
     */
    private function executeTool(ChatMessage $assistant, ToolCall $call, ?string $rationale = null): array
    {
        $tool = $this->tools->get($call->name);
        if ($tool === null) {
            return ['error' => "Unknown tool `{$call->name}`. Available: ".implode(', ', $this->tools->names()).'.'];
        }

        $started = microtime(true);
        try {
            $result = $tool->execute($call->arguments);
            $status = 'success';
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
        ToolExecutionLog::create([
            'chat_message_id' => $assistant->id,
            'tool_name' => $call->name,
            'rationale' => $rationale,
            'status' => $status,
            'input_parameters' => $call->arguments,
            'output_payload' => $result,
            'execution_time_ms' => $elapsed,
            'loggable_type' => $owner::class,
            'loggable_id' => $owner->getKey(),
        ]);

        return $result;
    }

    /**
     * The agent ends an answer with lines like `[[next: Check lab-web-02 as well]]`: follow-up
     * actions it proposes. They are removed from the text and returned as clickable suggestions.
     *
     * @return array{0: string, 1: list<string>}
     */
    private function extractSuggestions(string $answer): array
    {
        preg_match_all('/\[\[\s*next:\s*(.+?)\s*\]\]/is', $answer, $matches);
        $suggestions = collect($matches[1])
            ->map(fn (string $s) => Str::limit(trim(preg_replace('/\s+/', ' ', $s)), 140))
            ->filter()
            ->unique()
            ->take(3)
            ->values()
            ->all();

        $clean = trim(preg_replace('/\[\[\s*next:.*?\]\]/is', '', $answer) ?? $answer);

        return [$clean !== '' ? $clean : $answer, $suggestions];
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
