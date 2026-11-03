<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;

abstract class TestCase extends BaseTestCase
{
    protected string $runsDir;

    protected function setUp(): void
    {
        parent::setUp();

        // Feature tests render views without a Vite build, and never reach the real LLM or NVD.
        $this->withoutVite();
        Http::preventStrayRequests();

        $this->runsDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'aegis-test-runs-'.uniqid();
        File::ensureDirectoryExists($this->runsDir);
        config([
            'agent.llm.base_url' => 'https://llm.test/v1',
            'agent.llm.api_key' => 'sk-test',
            'agent.llm.model' => 'qwen3:14b',
            'agent.llm.tool_mode' => 'auto',
            'agent.nvd.base_url' => 'https://nvd.test/cves/2.0',
            'agent.harness.scope' => base_path('tests/fixtures/scope/lab_scope.json'),
            'agent.harness.runs_dir' => $this->runsDir,
            'agent.harness.planner' => 'scripted',
        ]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->runsDir);
        parent::tearDown();
    }

    /**
     * Copy the recorded port-scan run into the test runs directory under a run id.
     */
    protected function seedRecordedRun(string $runId = 'run-20260915T124800-test'): string
    {
        File::copyDirectory(base_path('tests/fixtures/run/port_scan'), $this->runsDir.DIRECTORY_SEPARATOR.$runId);

        return $runId;
    }

    /**
     * An OpenAI-style chat completion response body.
     *
     * @param  list<array{0: string, 1: array<string, mixed>}>  $toolCalls  [name, arguments]
     * @return array<string, mixed>
     */
    protected function llmReply(string $content = '', array $toolCalls = [], int $completionTokens = 50): array
    {
        $message = ['role' => 'assistant', 'content' => $content];
        if ($toolCalls) {
            $message['tool_calls'] = array_map(fn ($c, $i) => [
                'id' => 'call_'.$i,
                'type' => 'function',
                'function' => ['name' => $c[0], 'arguments' => json_encode($c[1])],
            ], $toolCalls, array_keys($toolCalls));
        }

        return [
            'choices' => [['index' => 0, 'message' => $message, 'finish_reason' => $toolCalls ? 'tool_calls' : 'stop']],
            'usage' => ['prompt_tokens' => 900, 'completion_tokens' => $completionTokens],
        ];
    }
}
