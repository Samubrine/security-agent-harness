<?php

namespace Tests\Feature;

use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\LogAnalyzer;
use App\Models\MalwareScanner;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class RelationalModelTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test User hasMany ChatSession and ChatSession belongsTo User.
     */
    public function test_user_chat_session_relationship(): void
    {
        $user = User::factory()->create();
        $session = ChatSession::factory()->create(['user_id' => $user->id]);

        $this->assertTrue($user->chatSessions->contains($session));
        $this->assertEquals($user->id, $session->user->id);
    }

    /**
     * Test ChatSession hasMany ChatMessage and ChatMessage belongsTo ChatSession.
     */
    public function test_chat_session_chat_message_relationship(): void
    {
        $session = ChatSession::factory()->create();
        $message = ChatMessage::factory()->create(['chat_session_id' => $session->id]);

        $this->assertTrue($session->chatMessages->contains($message));
        $this->assertEquals($session->id, $message->chatSession->id);
    }

    /**
     * Test ChatMessage hasMany ToolExecutionLog and ToolExecutionLog belongsTo ChatMessage.
     */
    public function test_chat_message_tool_execution_log_relationship(): void
    {
        $message = ChatMessage::factory()->create();
        $scanner = SecurityScanner::factory()->create();

        $log = ToolExecutionLog::factory()->create([
            'chat_message_id' => $message->id,
            'loggable_type' => SecurityScanner::class,
            'loggable_id' => $scanner->id,
        ]);

        $this->assertTrue($message->toolExecutionLogs->contains($log));
        $this->assertEquals($message->id, $log->chatMessage->id);
    }

    /**
     * Challenge 1: Test Polymorphic Logging across different Agent types.
     */
    public function test_polymorphic_tool_logging_for_specialized_agents(): void
    {
        $message = ChatMessage::factory()->create();

        $securityScanner = SecurityScanner::factory()->create(['name' => 'Nmap Scanner']);
        $malwareScanner = MalwareScanner::factory()->create(['name' => 'ClamAV Engine']);
        $logAnalyzer = LogAnalyzer::factory()->create(['name' => 'OWASP SQLi Analyzer']);

        $secLog = ToolExecutionLog::factory()->create([
            'chat_message_id' => $message->id,
            'loggable_type' => SecurityScanner::class,
            'loggable_id' => $securityScanner->id,
            'tool_name' => 'nmap_scan',
        ]);

        $malLog = ToolExecutionLog::factory()->create([
            'chat_message_id' => $message->id,
            'loggable_type' => MalwareScanner::class,
            'loggable_id' => $malwareScanner->id,
            'tool_name' => 'clamav_scan',
        ]);

        $anaLog = ToolExecutionLog::factory()->create([
            'chat_message_id' => $message->id,
            'loggable_type' => LogAnalyzer::class,
            'loggable_id' => $logAnalyzer->id,
            'tool_name' => 'sqli_scan',
        ]);

        // Verify morphTo resolution
        $this->assertInstanceOf(SecurityScanner::class, $secLog->loggable);
        $this->assertEquals('Nmap Scanner', $secLog->loggable->name);

        $this->assertInstanceOf(MalwareScanner::class, $malLog->loggable);
        $this->assertEquals('ClamAV Engine', $malLog->loggable->name);

        $this->assertInstanceOf(LogAnalyzer::class, $anaLog->loggable);
        $this->assertEquals('OWASP SQLi Analyzer', $anaLog->loggable->name);

        // Verify morphMany reverse resolution
        $this->assertTrue($securityScanner->toolExecutionLogs->contains($secLog));
        $this->assertTrue($malwareScanner->toolExecutionLogs->contains($malLog));
        $this->assertTrue($logAnalyzer->toolExecutionLogs->contains($anaLog));
    }

    /**
     * Test Cascade Deletion from ChatSession down to ToolExecutionLogs.
     */
    public function test_cascade_delete_integrity(): void
    {
        $session = ChatSession::factory()->create();
        $message = ChatMessage::factory()->create(['chat_session_id' => $session->id]);
        $scanner = SecurityScanner::factory()->create();

        $log = ToolExecutionLog::factory()->create([
            'chat_message_id' => $message->id,
            'loggable_type' => SecurityScanner::class,
            'loggable_id' => $scanner->id,
        ]);

        $this->assertDatabaseHas('chat_sessions', ['id' => $session->id]);
        $this->assertDatabaseHas('chat_messages', ['id' => $message->id]);
        $this->assertDatabaseHas('tool_execution_logs', ['id' => $log->id]);

        // Deleting the session must cascade to messages and logs
        $session->delete();

        $this->assertDatabaseMissing('chat_sessions', ['id' => $session->id]);
        $this->assertDatabaseMissing('chat_messages', ['id' => $message->id]);
        $this->assertDatabaseMissing('tool_execution_logs', ['id' => $log->id]);
    }

    /**
     * Challenge 2: Test Nested Eager Loading avoids N+1 query problem.
     */
    public function test_nested_eager_loading_avoids_n_plus_one_queries(): void
    {
        $session = ChatSession::factory()->create();

        // Create 10 messages, each with 2 tool logs
        for ($i = 0; $i < 10; $i++) {
            $msg = ChatMessage::factory()->create(['chat_session_id' => $session->id]);
            $scanner = SecurityScanner::factory()->create();
            $malware = MalwareScanner::factory()->create();

            ToolExecutionLog::factory()->create([
                'chat_message_id' => $msg->id,
                'loggable_type' => SecurityScanner::class,
                'loggable_id' => $scanner->id,
            ]);

            ToolExecutionLog::factory()->create([
                'chat_message_id' => $msg->id,
                'loggable_type' => MalwareScanner::class,
                'loggable_id' => $malware->id,
            ]);
        }

        // Count queries using nested Eager Loading
        DB::enableQueryLog();
        DB::flushQueryLog();

        $loadedSession = ChatSession::with([
            'user',
            'chatMessages.toolExecutionLogs.loggable',
        ])->find($session->id);

        // Access all nested properties
        $totalLogsAccessed = 0;
        foreach ($loadedSession->chatMessages as $msg) {
            foreach ($msg->toolExecutionLogs as $toolLog) {
                $this->assertNotNull($toolLog->loggable->name);
                $totalLogsAccessed++;
            }
        }

        $queryCount = count(DB::getQueryLog());

        // With 10 messages and 20 tool logs and 20 agents:
        // An unoptimized query would trigger 1 + 10 + 20 + 20 = 51 queries (N+1)!
        // With eager loading, it takes a fixed small number of queries (<= 6 queries):
        // 1. SELECT session
        // 2. SELECT user
        // 3. SELECT messages
        // 4. SELECT tool logs
        // 5. SELECT security scanners (morphTo)
        // 6. SELECT malware scanners (morphTo)
        $this->assertEquals(20, $totalLogsAccessed);
        $this->assertLessThanOrEqual(6, $queryCount, "Expected at most 6 queries with eager loading, but got {$queryCount}");
    }
}
