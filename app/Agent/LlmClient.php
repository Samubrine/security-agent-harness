<?php

namespace App\Agent;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

/**
 * Thin client for any OpenAI-compatible /chat/completions endpoint (the ITS gateway, Ollama,
 * LM Studio, vLLM...).
 *
 * It hides two differences between models:
 *  - reasoning models (Qwen3) wrap their thinking in <think>...</think>; it is split off into
 *    LlmReply::$reasoning so the UI can show it and the answer stays clean;
 *  - some gateways do not support the `tools` parameter. Qwen then writes tool calls as
 *    <tool_call>{"name": ..., "arguments": {...}}</tool_call> in plain text, which is parsed here.
 */
class LlmClient
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly ?string $apiKey,
        private readonly string $model,
        private readonly float $temperature = 0.2,
        private readonly int $timeout = 120,
    ) {}

    public static function fromConfig(): self
    {
        $config = config('agent.llm');

        return new self(
            baseUrl: $config['base_url'],
            apiKey: $config['api_key'],
            model: $config['model'],
            temperature: $config['temperature'],
            timeout: $config['timeout'],
        );
    }

    public function model(): string
    {
        return $this->model;
    }

    /**
     * @param  list<array<string, mixed>>  $messages  OpenAI-format messages
     * @param  list<array<string, mixed>>  $tools  OpenAI-format tool schemas; empty for no native tools
     *
     * @throws LlmException
     */
    public function chat(array $messages, array $tools = []): LlmReply
    {
        $payload = [
            'model' => $this->model,
            'messages' => $messages,
            'temperature' => $this->temperature,
            'stream' => false,
        ];
        if ($tools !== []) {
            $payload['tools'] = $tools;
            $payload['tool_choice'] = 'auto';
        }

        try {
            $response = Http::timeout($this->timeout)
                ->acceptJson()
                ->when($this->apiKey, fn ($http) => $http->withToken($this->apiKey))
                ->post($this->baseUrl.'/chat/completions', $payload);
        } catch (ConnectionException $e) {
            throw new LlmException('Could not reach the LLM gateway at '.$this->baseUrl.': '.$e->getMessage(), 0, $e);
        }

        if ($response->failed()) {
            throw new LlmException($this->describeFailure($response), $response->status());
        }

        $message = $response->json('choices.0.message');
        if (! is_array($message)) {
            throw new LlmException('The LLM gateway returned an unexpected response shape.');
        }

        return $this->parse($message, $response->json('usage') ?? []);
    }

    /**
     * @param  array<string, mixed>  $message
     * @param  array<string, mixed>  $usage
     */
    public function parse(array $message, array $usage = []): LlmReply
    {
        $raw = (string) ($message['content'] ?? '');
        [$content, $reasoning] = self::splitReasoning($raw);
        $reasoning = $reasoning ?? (isset($message['reasoning_content']) ? trim((string) $message['reasoning_content']) : null);

        $calls = [];
        foreach ($message['tool_calls'] ?? [] as $i => $call) {
            $arguments = $call['function']['arguments'] ?? [];
            if (is_string($arguments)) {
                $arguments = json_decode($arguments, true) ?? [];
            }
            $calls[] = new ToolCall(
                id: (string) ($call['id'] ?? 'call_'.$i),
                name: (string) ($call['function']['name'] ?? ''),
                arguments: is_array($arguments) ? $arguments : [],
            );
        }

        // Text fallback: the model wrote the call instead of using the API field.
        if ($calls === []) {
            [$content, $calls] = self::extractTextToolCalls($content);
        }

        return new LlmReply(
            content: trim($content),
            reasoning: $reasoning !== '' ? $reasoning : null,
            toolCalls: $calls,
            promptTokens: (int) ($usage['prompt_tokens'] ?? 0),
            completionTokens: (int) ($usage['completion_tokens'] ?? 0),
        );
    }

    /**
     * @return array{0: string, 1: ?string} [answer, reasoning]
     */
    public static function splitReasoning(string $text): array
    {
        $reasoning = [];
        $answer = preg_replace_callback('/<think>(.*?)<\/think>/is', function ($m) use (&$reasoning) {
            $reasoning[] = trim($m[1]);

            return '';
        }, $text) ?? $text;

        // An unclosed <think> means the model was cut off while still thinking.
        $open = stripos($answer, '<think>');
        if ($open !== false) {
            $reasoning[] = trim(substr($answer, $open + 7));
            $answer = substr($answer, 0, $open);
        }

        $joined = trim(implode("\n\n", array_filter($reasoning)));

        return [trim($answer), $joined !== '' ? $joined : null];
    }

    /**
     * @return array{0: string, 1: list<ToolCall>}
     */
    public static function extractTextToolCalls(string $content): array
    {
        $calls = [];
        $clean = preg_replace_callback('/<tool_call>\s*(\{.*?\})\s*<\/tool_call>/is', function ($m) use (&$calls) {
            $data = json_decode($m[1], true);
            if (is_array($data) && isset($data['name'])) {
                $args = $data['arguments'] ?? $data['parameters'] ?? [];
                if (is_string($args)) {
                    $args = json_decode($args, true) ?? [];
                }
                $calls[] = new ToolCall('call_text_'.count($calls), (string) $data['name'], is_array($args) ? $args : []);

                return '';
            }

            return $m[0];
        }, $content) ?? $content;

        return [trim($clean), $calls];
    }

    private function describeFailure(Response $response): string
    {
        $detail = $response->json('error.message') ?? $response->json('detail') ?? Str::limit($response->body(), 300);

        return match ($response->status()) {
            401, 403 => 'The LLM gateway rejected the API key (HTTP '.$response->status().'). Check LLM_API_KEY in .env.',
            default => 'The LLM gateway returned HTTP '.$response->status().': '.(is_string($detail) ? $detail : json_encode($detail)),
        };
    }
}
