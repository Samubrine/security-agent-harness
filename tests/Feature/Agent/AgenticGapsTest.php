<?php

namespace Tests\Feature\Agent;

use App\Agent\AgentRunner;
use App\Agent\ApprovalLedger;
use App\Agent\ClaimChecker;
use App\Agent\Harness\SkillCatalog;
use App\Agent\Tools\NeedsContext;
use App\Agent\Tools\RunInvestigationTool;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\EvidenceArtifact;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Tests\TestCase;

/**
 * The five gaps between the original design and the first implementation:
 * live progress, approvals, missing context, evidence + fact check, MCP-backed skill.
 */
class AgenticGapsTest extends TestCase
{
    use RefreshDatabase;

    /** @var list<list<string>> */
    private array $commands = [];

    /**
     * Pretend to be the harness. A version_check run without approval answers looks like the
     * recorded "denied" run (the inventory call was skipped); with answers, like the approved one.
     */
    private function fakeHarness(): void
    {
        Process::fake(function (PendingProcess $process) {
            $cmd = $process->command;
            $this->commands[] = $cmd;
            $skill = $cmd[array_search('--skill', $cmd, true) + 1];
            $fixture = match (true) {
                $skill !== 'version_check' => 'port_scan',
                in_array('--approval-answers', $cmd, true) => 'version_check_approved',
                default => 'version_check_denied',
            };
            $out = $cmd[array_search('--out', $cmd, true) + 1];
            File::copyDirectory(base_path('tests/fixtures/run/'.$fixture), $out);

            return Process::result(output: json_encode(['run_id' => $cmd[array_search('--run-id', $cmd, true) + 1], 'status' => 'completed']));
        });
    }

    private function chatWith(User $user, string $question): ChatSession
    {
        $session = ChatSession::factory()->create(['user_id' => $user->id, 'agent_mode' => 'autonomous_investigation']);
        ChatMessage::create(['chat_session_id' => $session->id, 'role' => 'user', 'content' => $question, 'token_count' => 5, 'sequence_number' => 1]);

        return $session;
    }

    // -- skills come from the harness's YAML files --------------------------------------------

    public function test_the_skill_catalog_reads_the_harness_skill_files(): void
    {
        $catalog = app(SkillCatalog::class);

        $this->assertSame(['entry_point', 'log_analysis', 'port_scan', 'version_check'], $catalog->names());
        $this->assertSame(['target' => 'scope_target'], $catalog->required('version_check'));
        $this->assertEqualsCanonicalizing(['corpus' => 'scope_fs_target', 'target' => 'scope_target'], $catalog->required('entry_point'));
        $this->assertStringContainsString('asset inventory', app(RunInvestigationTool::class)->description());
    }

    // -- gap 3: missing context is asked, not guessed ----------------------------------------

    public function test_a_missing_or_wrong_target_asks_the_operator_with_options_from_the_scope(): void
    {
        $this->fakeHarness();
        $tool = app(RunInvestigationTool::class);

        foreach ([[], ['target' => 'lab-logs'], ['target' => '10.0.0.5']] as $extra) {
            try {
                $tool->execute(['skill' => 'port_scan', 'objective' => 'scan it'] + $extra);
                $this->fail('expected NeedsContext');
            } catch (NeedsContext $e) {
                $this->assertSame('port_scan', $e->skill);
                $this->assertSame(['lab-web-01', 'lab-web-02'], $e->fields[0]['options']);
            }
        }
        Process::assertNothingRan();
    }

    public function test_the_agent_stops_and_shows_a_form_when_context_is_missing(): void
    {
        $this->fakeHarness();
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['run_investigation', ['skill' => 'port_scan', 'objective' => 'Scan the web server']]]))
            ->push($this->llmReply('should never be asked'))]);

        $reply = app(AgentRunner::class)->respond($this->chatWith(User::factory()->create(), 'Scan the web server'));

        $this->assertSame('context', $reply->pending_action['type']);
        $this->assertSame(['lab-web-01', 'lab-web-02'], $reply->pending_action['fields'][0]['options']);
        $this->assertStringContainsString('which machine', $reply->content);
        Http::assertSentCount(1); // the model was not asked to guess
    }

    public function test_choosing_a_target_continues_the_conversation(): void
    {
        $this->fakeHarness();
        $user = User::factory()->create();
        $session = $this->chatWith($user, 'Scan the web server');
        $asked = ChatMessage::create(['chat_session_id' => $session->id, 'role' => 'assistant', 'content' => 'Which machine?', 'token_count' => 1, 'sequence_number' => 2,
            'pending_action' => ['type' => 'context', 'skill' => 'port_scan', 'objective' => 'Scan', 'fields' => [['name' => 'target', 'label' => 'Which machine should be checked?', 'options' => ['lab-web-01', 'lab-web-02']]]]]);
        Http::fake(['llm.test/*' => Http::response($this->llmReply('Scanned.'))]);

        $this->actingAs($user)->post(route('chat.resolve', [$session->id, $asked->id]), ['target' => '8.8.8.8'])->assertSessionHasErrors('target');
        $this->actingAs($user)->post(route('chat.resolve', [$session->id, $asked->id]), ['target' => 'lab-web-02'])->assertRedirect();

        $this->assertSame('lab-web-02', $asked->fresh()->pending_action['resolved']);
        $this->assertStringContainsString('Use lab-web-02 for the port scan', $session->chatMessages()->where('role', 'user')->latest('id')->value('content'));
        $this->actingAs($user)->post(route('chat.resolve', [$session->id, $asked->id]), ['target' => 'lab-web-01'])->assertSessionHas('error');
    }

    // -- gap 2 + 5: an approval-gated MCP step -------------------------------------------------

    public function test_the_harness_is_run_strict_with_the_mcp_servers_and_approvals_become_buttons(): void
    {
        $this->fakeHarness();
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['run_investigation', ['skill' => 'version_check', 'target' => 'lab-web-01', 'objective' => 'Was Tomcat patched?']]]))
            ->push($this->llmReply('The inventory check needs your approval.'))]);

        $reply = app(AgentRunner::class)->respond($this->chatWith(User::factory()->create(), 'Was Tomcat patched?'));

        $cmd = $this->commands[0];
        $this->assertContains('--strict', $cmd);
        $this->assertSame(base_path('config/mcp_servers.json'), $cmd[array_search('--mcp-config', $cmd, true) + 1]);
        $this->assertNotContains('--approval-answers', $cmd);

        $action = $reply->pending_action;
        $this->assertSame('approval', $action['type']);
        $this->assertSame('version_check', $action['skill']);
        $this->assertSame('lab-web-01', $action['target']);
        $this->assertSame('the asset inventory (MCP server)', $action['requests'][0]['provider']);
        $this->assertStringContainsString('attacker could control', $action['requests'][0]['reason']);
    }

    public function test_approving_reruns_with_exactly_one_yes_and_the_sources_are_cross_checked(): void
    {
        $this->fakeHarness();
        $user = User::factory()->create();
        $session = $this->chatWith($user, 'Was Tomcat patched?');
        $asked = ChatMessage::create(['chat_session_id' => $session->id, 'role' => 'assistant', 'content' => 'Needs approval.', 'token_count' => 1, 'sequence_number' => 2,
            'pending_action' => ['type' => 'approval', 'skill' => 'version_check', 'target' => 'lab-web-01', 'objective' => 'Was Tomcat patched?',
                'requests' => [['provider' => 'the asset inventory (MCP server)', 'capability' => 'service.enumerate', 'reason' => 'third-party']]]]);
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['run_investigation', ['skill' => 'version_check', 'target' => 'lab-web-01', 'objective' => 'Was Tomcat patched?']]]))
            ->push($this->llmReply('Not patched: the scan sees 9.0.30, the inventory claims 9.0.31.'))]);

        $this->actingAs($user)->post(route('chat.resolve', [$session->id, $asked->id]), ['decision' => 'approve'])->assertRedirect();

        $cmd = end($this->commands);
        $this->assertSame('yes', $cmd[array_search('--approval-answers', $cmd, true) + 1]);
        $this->assertSame('approve', $asked->fresh()->pending_action['resolved']);
        $output = $session->chatMessages()->where('role', 'assistant')->latest('id')->first()->toolExecutionLogs->first()->output_payload;
        $this->assertSame([], $output['approval_needed']);
        $relations = collect($output['cross_checks'])->pluck('relation', 'subject')->all();
        $this->assertSame('conflict', $relations['lab-web-01 port 8080']);
        $this->assertSame('agreement', $relations['lab-web-01 port 22']);
        $this->assertSame([], app(ApprovalLedger::class)->take('version_check', 'lab-web-01'), 'approvals are used once');
    }

    // -- gap 1: live progress ------------------------------------------------------------------

    public function test_a_streaming_request_receives_each_step_as_ndjson(): void
    {
        $this->fakeHarness();
        $user = User::factory()->create();
        $session = $this->chatWith($user, 'hi');
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['run_investigation', ['skill' => 'port_scan', 'target' => 'lab-web-01', 'objective' => 'x']]]))
            ->push($this->llmReply('Done.'))]);

        $response = $this->actingAs($user)->withHeaders(['Accept' => 'application/x-ndjson'])
            ->post(route('chat.message', $session->id), ['content' => 'Is lab-web-01 safe?']);

        $response->assertOk();
        $this->assertStringStartsWith('application/x-ndjson', $response->headers->get('Content-Type'));
        $events = array_map(fn ($l) => json_decode($l, true), array_filter(explode("\n", $response->streamedContent())));
        $types = array_column($events, 'type');
        $this->assertSame('started', $types[0]);
        $this->assertSame('done', end($types));
        $this->assertContains('tool_started', $types);
        $this->assertContains('tool_finished', $types);
        $this->assertContains('harness', $types);
        $this->assertContains('Running the port scan on lab-web-01', array_column($events, 'label'));
    }

    // -- gap 4: evidence artifacts and the fact check ---------------------------------------

    public function test_tool_results_become_hashed_evidence_and_the_answer_is_fact_checked(): void
    {
        $this->fakeHarness();
        Http::fake(['llm.test/*' => Http::sequence()
            ->push($this->llmReply('', [['run_investigation', ['skill' => 'port_scan', 'target' => 'lab-web-01', 'objective' => 'x']]]))
            ->push($this->llmReply("Tomcat has CVE-2020-1938 (CVSS 9.8). CVE-2099-0001 is bad too. CVE-2021-23017 scores 9.9 out of 10. Run run-20990101T000000-zzzz agrees."))]);

        $reply = app(AgentRunner::class)->respond($this->chatWith(User::factory()->create(), 'Is lab-web-01 safe?'));

        $artifact = EvidenceArtifact::sole();
        $this->assertSame('run_investigation', $artifact->kind);
        $this->assertStringStartsWith('harness:run-', $artifact->source);
        $this->assertSame(hash('sha256', EvidenceArtifact::canonicalJson($artifact->content)), $artifact->sha256);

        $check = $reply->claim_check;
        $problems = collect($check['issues'])->pluck('problem', 'claim')->all();
        $this->assertArrayHasKey('CVE-2099-0001', $problems);
        $this->assertSame('the evidence says 7.7', $problems['CVE-2021-23017 CVSS 9.9']);
        $this->assertArrayHasKey('run-20990101T000000-zzzz', $problems);
        $this->assertArrayNotHasKey('CVE-2020-1938', $problems);
        $this->assertArrayNotHasKey('CVE-2020-1938 CVSS 9.8', $problems);
    }

    public function test_an_exploited_claim_is_checked_against_the_nvd_lookup(): void
    {
        $session = ChatSession::factory()->create();
        $log = \App\Models\ToolExecutionLog::create(['chat_message_id' => ChatMessage::create(['chat_session_id' => $session->id, 'role' => 'assistant', 'content' => 'x', 'token_count' => 1, 'sequence_number' => 1])->id,
            'tool_name' => 'lookup_cve', 'status' => 'success', 'input_parameters' => [], 'output_payload' => [], 'execution_time_ms' => 1,
            'loggable_type' => \App\Models\KnowledgeSource::class, 'loggable_id' => 1]);
        $content = ['id' => 'CVE-2023-38408', 'cvss_score' => 9.8, 'known_exploited' => false];
        EvidenceArtifact::create(['chat_session_id' => $session->id, 'tool_execution_log_id' => $log->id, 'kind' => 'lookup_cve', 'source' => 'nvd', 'sha256' => str_repeat('a', 64), 'content' => $content]);

        $check = app(ClaimChecker::class)->check('CVE-2023-38408 is actively exploited. CVE-2023-38408 is not in KEV.', EvidenceArtifact::all());

        $this->assertCount(1, $check['issues']);
        $this->assertStringContainsString('known-exploited', $check['issues'][0]['problem']);
    }

    public function test_the_conversation_page_shows_the_fact_check_and_the_approval_buttons(): void
    {
        $user = User::factory()->create();
        $session = $this->chatWith($user, 'q');
        ChatMessage::create(['chat_session_id' => $session->id, 'role' => 'assistant', 'content' => 'Answer.', 'token_count' => 1, 'sequence_number' => 2,
            'claim_check' => ['checked' => 3, 'supported' => 2, 'issues' => [['claim' => 'CVE-2099-0001', 'problem' => 'does not appear in any tool result']], 'artifacts' => 2],
            'pending_action' => ['type' => 'approval', 'skill' => 'version_check', 'target' => 'lab-web-01', 'requests' => [['provider' => 'the asset inventory (MCP server)', 'capability' => 'service.enumerate', 'reason' => 'it is a medium-risk, third-party (MCP) tool']]]]);

        $this->actingAs($user)->get(route('chat.show', $session->id))
            ->assertOk()
            ->assertSee('2 of 3 checkable facts match the evidence')
            ->assertSee('CVE-2099-0001')
            ->assertSee('APPROVAL NEEDED')
            ->assertSee('Approve and run again')
            ->assertSee('the asset inventory (MCP server)');
    }
}
