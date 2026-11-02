<?php

namespace Tests\Feature\Agent;

use App\Agent\AgentRunner;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\KnowledgeSource;
use App\Models\ToolExecutionLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class AgentRunnerTest extends TestCase
{
    use RefreshDatabase;

    private function sessionWithQuestion(string $question): ChatSession
    {
        $session = ChatSession::factory()->create(['agent_mode' => 'autonomous_investigation']);
        ChatMessage::create(['chat_session_id' => $session->id, 'role' => 'user', 'content' => $question, 'token_count' => 5, 'sequence_number' => 1]);

        return $session;
    }

    private function nvdRecord(): array
    {
        return ['vulnerabilities' => [['cve' => [
            'id' => 'CVE-2020-1938',
            'published' => '2020-02-24T22:15:11.953',
            'vulnStatus' => 'Analyzed',
            'descriptions' => [['lang' => 'en', 'value' => 'Ghostcat: the AJP connector in Apache Tomcat trusts incoming connections.']],
            'metrics' => ['cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 9.8, 'baseSeverity' => 'CRITICAL', 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']]]],
            'weaknesses' => [['description' => [['lang' => 'en', 'value' => 'NVD-CWE-Other']]]],
            'cisaExploitAdd' => '2022-03-03',
            'cisaRequiredAction' => 'Apply updates per vendor instructions.',
            'references' => [['url' => 'https://tomcat.apache.org/security-9.html', 'tags' => ['Vendor Advisory']]],
        ]]]];
    }

    public function test_the_agent_chains_tools_it_chose_and_logs_each_call(): void
    {
        $runId = $this->seedRecordedRun();
        Http::fake([
            'nvd.test/*' => Http::response($this->nvdRecord()),
            'llm.test/*' => Http::sequence()
                ->push($this->llmReply('', [['list_investigations', []]]))
                ->push($this->llmReply('<think>The critical CVE first.</think>', [['lookup_cve', ['cve_id' => 'CVE-2020-1938']]]))
                ->push($this->llmReply("**Verdict: at risk.** Run `{$runId}` found Tomcat 9.0.30 (CVE-2020-1938, CVSS 9.8, exploited in the wild).", [], 120)),
        ]);

        $session = $this->sessionWithQuestion('Is lab-web-01 safe?');
        $reply = app(AgentRunner::class)->respond($session);

        $this->assertSame('assistant', $reply->role);
        $this->assertStringContainsString('CVE-2020-1938', $reply->content);
        $this->assertStringContainsString('The critical CVE first.', $reply->reasoning);
        $this->assertSame(220, $reply->token_count);

        $logs = ToolExecutionLog::orderBy('id')->get();
        $this->assertSame(['list_investigations', 'lookup_cve'], $logs->pluck('tool_name')->all());
        $this->assertTrue($logs->every(fn ($l) => $l->status === 'success' && $l->chat_message_id === $reply->id));
        $this->assertInstanceOf(KnowledgeSource::class, $logs[1]->loggable);
        $this->assertSame('NVD CVE Database', $logs[1]->loggable->name);
        $this->assertSame(9.8, $logs[1]->output_payload['cvss_score']);
        $this->assertTrue($logs[1]->output_payload['known_exploited']);
        $this->assertSame($runId, $logs[0]->output_payload['investigations'][0]['run_id']);

        // The tool results were fed back to the model in OpenAI's tool-message format.
        Http::assertSent(function (Request $r) {
            $last = collect($r['messages'] ?? [])->last();

            return str_contains($r->url(), 'llm.test') && ($last['role'] ?? null) === 'tool'
                && str_contains($last['content'], 'Ghostcat');
        });
    }

    public function test_the_agents_stated_reason_and_suggested_next_steps_are_kept(): void
    {
        $this->seedRecordedRun();
        Http::fake([
            'llm.test/*' => Http::sequence()
                ->push($this->llmReply("I'll look at earlier results first, because they may already answer this.", [['list_investigations', []]]))
                ->push($this->llmReply("Not safe yet: one old Tomcat version.\n\n[[next: Check lab-web-02 as well]]\n[[next: Explain how to fix Tomcat]]\n[[next: Check lab-web-02 as well]]")),
        ]);

        $reply = app(AgentRunner::class)->respond($this->sessionWithQuestion('Is lab-web-01 safe?'));

        $log = $reply->toolExecutionLogs->first();
        $this->assertSame("I'll look at earlier results first, because they may already answer this.", $log->rationale);
        $this->assertSame('Not safe yet: one old Tomcat version.', $reply->content);
        $this->assertSame(['Check lab-web-02 as well', 'Explain how to fix Tomcat'], $reply->suggestions);
    }

    public function test_a_bad_tool_call_is_reported_back_to_the_model_instead_of_crashing(): void
    {
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['lookup_cve', ['cve_id' => 'not-a-cve']]]))
            ->push($this->llmReply('', [['delete_everything', []]]))
            ->push($this->llmReply('Sorry, that is not a valid CVE id.')),
        ]);

        $reply = app(AgentRunner::class)->respond($this->sessionWithQuestion('look up not-a-cve'));

        $this->assertSame('Sorry, that is not a valid CVE id.', $reply->content);
        $log = ToolExecutionLog::sole();
        $this->assertSame('failed', $log->status);
        $this->assertStringContainsString('CVE-2021-41773', $log->output_payload['error']);
        Http::assertSent(fn (Request $r) => str_contains(json_encode($r['messages'] ?? []), 'Unknown tool `delete_everything`'));
    }

    public function test_the_loop_stops_at_the_step_limit_and_still_answers(): void
    {
        config(['agent.max_steps' => 2]);
        $this->seedRecordedRun();
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['list_investigations', []]]))
            ->push($this->llmReply('', [['list_investigations', []]]))
            ->push($this->llmReply('Here is what I have so far.')),
        ]);

        $reply = app(AgentRunner::class)->respond($this->sessionWithQuestion('loop forever'));

        $this->assertSame('Here is what I have so far.', $reply->content);
        $this->assertSame(2, ToolExecutionLog::count());
        Http::assertSentCount(3);
    }

    public function test_it_falls_back_to_text_tool_calls_when_the_gateway_rejects_tools(): void
    {
        $this->seedRecordedRun();
        Http::fake(['llm.test/*' => Http::sequence()
            ->push(['error' => ['message' => 'tools not supported']], 400)
            ->push($this->llmReply('<tool_call>{"name": "list_investigations", "arguments": {}}</tool_call>'))
            ->push($this->llmReply('One earlier investigation found 5 issues.')),
        ]);

        $reply = app(AgentRunner::class)->respond($this->sessionWithQuestion('what did we find?'));

        $this->assertSame('One earlier investigation found 5 issues.', $reply->content);
        $this->assertSame('list_investigations', ToolExecutionLog::sole()->tool_name);
        Http::assertSent(fn (Request $r) => ! isset($r['tools'])
            && str_contains($r['messages'][0]['content'], '<tool_call>')
            && str_contains(collect($r['messages'])->last()['content'], '<tool_response name="list_investigations">'));
    }

    public function test_an_unreachable_llm_produces_an_explanatory_reply(): void
    {
        Http::fake(['llm.test/*' => Http::response(['error' => ['message' => 'bad key']], 401)]);

        $reply = app(AgentRunner::class)->respond($this->sessionWithQuestion('halo'));

        $this->assertStringContainsString('could not be reached', $reply->content);
        $this->assertStringContainsString('LLM_API_KEY', $reply->content);
    }
}
