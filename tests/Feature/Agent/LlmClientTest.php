<?php

namespace Tests\Feature\Agent;

use App\Agent\LlmClient;
use App\Agent\LlmException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class LlmClientTest extends TestCase
{
    public function test_it_sends_the_bearer_token_model_and_tools(): void
    {
        Http::fake(['llm.test/*' => Http::response($this->llmReply('Halo!'))]);

        $reply = app(LlmClient::class)->chat([['role' => 'user', 'content' => 'halo']], [['type' => 'function', 'function' => ['name' => 'x']]]);

        $this->assertSame('Halo!', $reply->content);
        Http::assertSent(fn (Request $r) => $r->url() === 'https://llm.test/v1/chat/completions'
            && $r->hasHeader('Authorization', 'Bearer sk-test')
            && $r['model'] === 'qwen3:14b'
            && $r['tools'][0]['function']['name'] === 'x');
    }

    public function test_reasoning_is_split_from_the_answer(): void
    {
        Http::fake(['llm.test/*' => Http::response($this->llmReply("<think>\nThe user greets me.\n</think>\n\nHalo juga!"))]);

        $reply = app(LlmClient::class)->chat([['role' => 'user', 'content' => 'halo']]);

        $this->assertSame('Halo juga!', $reply->content);
        $this->assertSame('The user greets me.', $reply->reasoning);
    }

    public function test_native_tool_calls_are_parsed(): void
    {
        Http::fake(['llm.test/*' => Http::response($this->llmReply('', [['lookup_cve', ['cve_id' => 'CVE-2021-41773']]]))]);

        $reply = app(LlmClient::class)->chat([['role' => 'user', 'content' => 'x']]);

        $this->assertTrue($reply->wantsTools());
        $this->assertSame('lookup_cve', $reply->toolCalls[0]->name);
        $this->assertSame(['cve_id' => 'CVE-2021-41773'], $reply->toolCalls[0]->arguments);
    }

    public function test_tool_calls_written_as_text_are_parsed(): void
    {
        $text = "<think>need data</think>\nLet me check.\n<tool_call>\n{\"name\": \"search_cves\", \"arguments\": {\"keyword\": \"nginx 1.18.0\"}}\n</tool_call>";
        Http::fake(['llm.test/*' => Http::response($this->llmReply($text))]);

        $reply = app(LlmClient::class)->chat([['role' => 'user', 'content' => 'x']]);

        $this->assertSame('search_cves', $reply->toolCalls[0]->name);
        $this->assertSame(['keyword' => 'nginx 1.18.0'], $reply->toolCalls[0]->arguments);
        $this->assertSame('Let me check.', $reply->content);
    }

    public function test_a_rate_limited_request_is_retried(): void
    {
        Http::fake(['llm.test/*' => Http::sequence()
            ->push(['error' => ['message' => 'Rate limit reached. Please try again in 0.01s.']], 429, ['Retry-After' => '0'])
            ->push($this->llmReply('Halo!'))]);

        $reply = app(LlmClient::class)->chat([['role' => 'user', 'content' => 'halo']]);

        $this->assertSame('Halo!', $reply->content);
        Http::assertSentCount(2);
    }

    public function test_a_rejected_key_gives_an_actionable_error(): void
    {
        Http::fake(['llm.test/*' => Http::response(['error' => ['message' => 'invalid key']], 401)]);

        $this->expectException(LlmException::class);
        $this->expectExceptionMessage('LLM_API_KEY');

        app(LlmClient::class)->chat([['role' => 'user', 'content' => 'x']]);
    }
}
