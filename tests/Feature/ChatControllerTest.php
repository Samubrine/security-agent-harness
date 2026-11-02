<?php

namespace Tests\Feature;

use App\Models\ChatSession;
use App\Models\SecurityScanner;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
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
        $response->assertSee('Agentic AI Chat Sessions');
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

    public function test_authenticated_user_can_send_message_and_trigger_agent_tool(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);
        SecurityScanner::factory()->create();

        $response = $this->actingAs($user)->post(route('chat.message', $session->id), [
            'content' => 'Scan port network 192.168.1.1/24 for vulnerabilities',
        ]);

        $response->assertRedirect(route('chat.show', $session->id));
        $this->assertDatabaseHas('chat_messages', [
            'chat_session_id' => $session->id,
            'role' => 'user',
        ]);
        $this->assertDatabaseHas('chat_messages', [
            'chat_session_id' => $session->id,
            'role' => 'assistant',
        ]);
        $this->assertDatabaseHas('tool_execution_logs', [
            'tool_name' => 'nmap_stealth_recon',
        ]);
    }
}
