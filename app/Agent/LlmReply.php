<?php

namespace App\Agent;

/**
 * One assistant turn, normalised across native tool calling and the text fallback.
 */
final class LlmReply
{
    /**
     * @param  list<ToolCall>  $toolCalls
     */
    public function __construct(
        public readonly string $content,
        public readonly ?string $reasoning,
        public readonly array $toolCalls,
        public readonly int $promptTokens = 0,
        public readonly int $completionTokens = 0,
    ) {}

    public function wantsTools(): bool
    {
        return $this->toolCalls !== [];
    }
}
