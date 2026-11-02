<?php

namespace Tests\Feature;

use App\Models\ChatSession;
use App\Models\KnowledgeSource;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class ChatControllerTest extends TestCase
{
    use RefreshDatabase;

    public function test_authenticated_user_can_view_chat_index(): void
    {
        $user = User::factory()->create();
        ChatSession::factory()->count(3)->create(['user_id' => $user->id]);

        $response = $this->actingAs($user)->get(route('chat.index'));

        $response->assertStatus(200);
        $response->assertSee('Is your lab safe?');
        $response->assertSee('Run a full check-up');
        $response->assertSee('How this agent works');
    }

    public function test_authenticated_user_can_view_chat_show_optimized_and_lazy_modes(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        // Optimized mode
        $responseOpt = $this->actingAs($user)->get(route('chat.show', ['id' => $session->id, 'mode' => 'optimized']));
        $responseOpt->assertStatus(200);
        $responseOpt->assertSee('Tantangan 2: Teroptimasi');

        // Lazy mode
        $responseLazy = $this->actingAs($user)->get(route('chat.show', ['id' => $session->id, 'mode' => 'lazy']));
        $responseLazy->assertStatus(200);
        $responseLazy->assertSee('Demonstrasi Masalah N+1 Query');
    }

    public function test_authenticated_user_can_create_chat_session(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->post(route('chat.store'), [
            'title' => 'Investigasi Zero Day Breach',
            'agent_mode' => 'autonomous_investigation',
        ]);

        $session = ChatSession::where('title', 'Investigasi Zero Day Breach')->first();
        $this->assertNotNull($session);
        $response->assertRedirect(route('chat.show', $session->id));
        $this->assertDatabaseHas('chat_sessions', ['title' => 'Investigasi Zero Day Breach']);
    }

    public function test_sending_a_message_runs_the_agent_and_logs_its_tool_calls(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);
        Http::fake([
            'nvd.test/*' => Http::response(['vulnerabilities' => [['cve' => [
                'id' => 'CVE-2021-41773',
                'descriptions' => [['lang' => 'en', 'value' => 'Path traversal in Apache HTTP Server 2.4.49.']],
                'metrics' => ['cvssMetricV31' => [['type' => 'Primary', 'cvssData' => ['baseScore' => 7.5, 'baseSeverity' => 'HIGH']]]],
            ]]]]),
            'llm.test/*' => Http::sequence()
                ->push($this->llmReply('', [['lookup_cve', ['cve_id' => 'CVE-2021-41773']]]))
                ->push($this->llmReply('CVE-2021-41773 is a **path traversal** bug (CVSS 7.5).')),
        ]);

        $response = $this->actingAs($user)->post(route('chat.message', $session->id), [
            'content' => 'Explain CVE-2021-41773',
        ]);

        $response->assertRedirect(route('chat.show', $session->id).'#latest');
        $this->assertDatabaseHas('chat_messages', ['chat_session_id' => $session->id, 'role' => 'user', 'content' => 'Explain CVE-2021-41773']);
        $this->assertDatabaseHas('chat_messages', ['chat_session_id' => $session->id, 'role' => 'assistant', 'content' => 'CVE-2021-41773 is a **path traversal** bug (CVSS 7.5).']);
        $this->assertDatabaseHas('tool_execution_logs', ['tool_name' => 'lookup_cve', 'status' => 'success', 'loggable_type' => KnowledgeSource::class]);

        // The answer is rendered as Markdown and the tool call is shown with its real fields.
        $this->actingAs($user)->get(route('chat.show', $session->id))
            ->assertOk()
            ->assertSee('<strong>path traversal</strong>', false)
            ->assertSee('NVD CVE Database')
            ->assertSee('CVSS 7.5');
    }

    public function test_agent_answers_cannot_inject_html(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);
        Http::fake(['llm.test/*' => Http::response($this->llmReply('<script>alert(1)</script> [x](javascript:alert(1))'))]);

        $this->actingAs($user)->post(route('chat.message', $session->id), ['content' => 'hi']);

        $this->actingAs($user)->get(route('chat.show', $session->id))
            ->assertOk()
            ->assertDontSee('<script>alert(1)</script>', false)
            ->assertDontSee('href="javascript:', false);
    }

    public function test_users_cannot_see_or_post_to_each_others_sessions(): void
    {
        $owner = User::factory()->create();
        $intruder = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $owner->id, 'title' => 'Owner only investigation']);

        $this->actingAs($intruder)->get(route('chat.show', $session->id))->assertNotFound();
        $this->actingAs($intruder)->get(route('chat.show', ['id' => $session->id, 'mode' => 'lazy']))->assertNotFound();
        $this->actingAs($intruder)->post(route('chat.message', $session->id), ['content' => 'hello'])->assertNotFound();
        $this->actingAs($intruder)->get(route('chat.index'))->assertDontSee('Owner only investigation');
        $this->assertDatabaseMissing('chat_messages', ['content' => 'hello']);
    }

    public function test_asking_on_the_home_page_starts_a_conversation_and_answers_it(): void
    {
        $user = User::factory()->create();
        Http::fake(['llm.test/*' => Http::response($this->llmReply("Mostly fine.\n[[next: Scan lab-web-02]]"))]);

        $response = $this->actingAs($user)->post(route('chat.ask'), ['content' => 'Is lab-web-01 safe?']);

        $session = ChatSession::where('user_id', $user->id)->firstOrFail();
        $response->assertRedirect(route('chat.show', $session->id).'#latest');
        $this->assertSame('Is lab-web-01 safe?', $session->title);
        $this->assertSame(['system', 'user', 'assistant'], $session->chatMessages()->orderBy('sequence_number')->pluck('role')->all());
        $this->actingAs($user)->get(route('chat.show', $session->id))->assertSee('Scan lab-web-02')->assertSee('Mostly fine.');
    }

    public function test_the_full_checkup_button_gives_the_agent_a_goal_without_a_question(): void
    {
        $user = User::factory()->create();
        Http::fake(['llm.test/*' => Http::response($this->llmReply('Briefing.'))]);

        $this->actingAs($user)->post(route('chat.checkup'))->assertRedirect();

        $session = ChatSession::where('user_id', $user->id)->firstOrFail();
        $this->assertStringStartsWith('Full lab check-up', $session->title);
        $this->assertStringContainsString('every machine and log source', $session->chatMessages()->where('role', 'user')->value('content'));
    }
}
