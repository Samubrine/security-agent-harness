<?php

namespace Tests\Feature;

use App\Livewire\ChatBox;
use App\Livewire\ChatSidebar;
use App\Livewire\CodeVisualizer;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;
use Tests\TestCase;

class LivewireAgenticWorkspaceTest extends TestCase
{
    use RefreshDatabase;

    public function test_livewire_components_rendered_on_chat_show(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        $response = $this->actingAs($user)->get(route('chat.show', $session->id));

        $response->assertStatus(200);
        $response->assertSeeLivewire(ChatSidebar::class);
        $response->assertSeeLivewire(ChatBox::class);
        $response->assertSeeLivewire(CodeVisualizer::class);
    }

    public function test_chat_sidebar_lists_sessions_and_isolates_user_data(): void
    {
        $userA = User::factory()->create(['name' => 'Operator A']);
        $userB = User::factory()->create(['name' => 'Operator B']);

        $sessionA = ChatSession::factory()->create([
            'user_id' => $userA->id,
            'title' => 'Investigasi Internal User A',
        ]);

        $sessionB = ChatSession::factory()->create([
            'user_id' => $userB->id,
            'title' => 'Rahasia Security User B',
        ]);

        // User A only sees session A, not session B
        Livewire::actingAs($userA)
            ->test(ChatSidebar::class, ['initialSessionId' => $sessionA->id])
            ->assertSee('Investigasi Internal User A')
            ->assertDontSee('Rahasia Security User B');
    }

    public function test_chat_sidebar_can_create_new_session_and_dispatch_event(): void
    {
        $user = User::factory()->create();

        Livewire::actingAs($user)
            ->test(ChatSidebar::class)
            ->set('newTitle', 'Audit Nginx Reverse Proxy')
            ->set('newAgentMode', 'strict_compliance_audit')
            ->call('createSession')
            ->assertHasNoErrors()
            ->assertDispatched('session-selected')
            ->assertDispatched('session-created');

        $this->assertDatabaseHas('chat_sessions', [
            'user_id' => $user->id,
            'title' => 'Audit Nginx Reverse Proxy',
            'agent_mode' => 'strict_compliance_audit',
        ]);
    }

    public function test_chat_sidebar_validates_required_title(): void
    {
        $user = User::factory()->create();

        Livewire::actingAs($user)
            ->test(ChatSidebar::class)
            ->set('newTitle', 'ab') // Kurang dari 3 karakter
            ->call('createSession')
            ->assertHasErrors(['newTitle' => 'min']);
    }

    public function test_chat_box_validates_prompt_and_tracks_character_count(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        Livewire::actingAs($user)
            ->test(ChatBox::class, ['initialSessionId' => $session->id])
            ->set('prompt', 'Halo')
            ->assertSet('charCount', 4)
            ->assertSet('remainingChars', 996)
            ->set('prompt', '')
            ->call('kirim')
            ->assertHasErrors(['prompt']);
    }

    public function test_chat_box_stores_user_prompt_physically_in_database(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        Livewire::actingAs($user)
            ->test(ChatBox::class, ['initialSessionId' => $session->id])
            ->set('prompt', 'Periksa apakah port 22 terbuka pada lab target')
            ->call('kirim');

        // Pastikan prompt tersimpan secara fisik di database MySQL (Slide 31 & 35)
        $this->assertDatabaseHas('chat_messages', [
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => 'Periksa apakah port 22 terbuka pada lab target',
        ]);
    }

    public function test_code_visualizer_listens_to_code_detected_event(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        Livewire::actingAs($user)
            ->test(CodeVisualizer::class, ['initialSessionId' => $session->id])
            ->dispatch('code-detected', [
                'language' => 'python',
                'code' => 'import nmap\nscanner = nmap.PortScanner()',
                'filename' => 'nmap_probe.py',
                'sessionId' => $session->id,
            ])
            ->assertSet('language', 'python')
            ->assertSet('filename', 'nmap_probe.py')
            ->assertSee('import nmap');
    }

    public function test_code_visualizer_polls_tool_status_from_database(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        $message = ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'assistant',
            'content' => 'Scanning finished.',
            'sequence_number' => 1,
        ]);

        $scanner = SecurityScanner::create([
            'name' => 'Nmap Scanner',
            'scanner_type' => 'network_port',
            'version' => '7.94',
            'configuration' => ['ports' => '80,443'],
        ]);

        ToolExecutionLog::create([
            'chat_message_id' => $message->id,
            'loggable_type' => SecurityScanner::class,
            'loggable_id' => $scanner->id,
            'tool_name' => 'nmap_port_scan',
            'parameters' => ['target' => '127.0.0.1'],
            'status' => 'success',
            'duration_ms' => 145,
            'started_at' => now(),
            'finished_at' => now(),
        ]);

        Livewire::actingAs($user)
            ->test(CodeVisualizer::class, ['initialSessionId' => $session->id])
            ->call('pollToolStatus')
            ->assertSet('toolStatus', 'SUKSES')
            ->assertSet('activeToolName', 'nmap_port_scan')
            ->assertSet('progressPercent', 100);
    }

    public function test_code_visualizer_can_execute_code_in_sandbox(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'assistant',
            'content' => 'Ready for execution.',
            'sequence_number' => 1,
        ]);

        $test = Livewire::actingAs($user)
            ->test(CodeVisualizer::class, ['initialSessionId' => $session->id])
            ->call('loadPreset', 'bash')
            ->assertSet('language', 'bash')
            ->call('executeCode')
            ->assertSet('toolStatus', 'SUKSES')
            ->assertSet('progressPercent', 100);

        $this->assertNotNull($test->get('executionOutput'));

        $this->assertDatabaseHas('tool_execution_logs', [
            'tool_name' => 'exec:nginx_mitigation.sh',
            'status' => 'success',
        ]);
    }
}
