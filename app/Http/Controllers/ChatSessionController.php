<?php

namespace App\Http\Controllers;

use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\LogAnalyzer;
use App\Models\MalwareScanner;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;

class ChatSessionController extends Controller
{
    /**
     * Display a listing of all chat sessions.
     */
    public function index(): View
    {
        $chatSessions = ChatSession::with(['user'])
            ->withCount(['chatMessages'])
            ->latest()
            ->paginate(10);

        $scannersCount = SecurityScanner::count();
        $malwareCount = MalwareScanner::count();
        $analyzerCount = LogAnalyzer::count();
        $totalLogsCount = ToolExecutionLog::count();

        return view('chat.index', compact(
            'chatSessions',
            'scannersCount',
            'malwareCount',
            'analyzerCount',
            'totalLogsCount'
        ));
    }

    /**
     * Display the specified chat session with nested Eager Loading optimization.
     *
     * Challenge 2: Optimasi Kueri Riwayat Obrolan
     * Allows comparing Optimized Eager Loading vs Unoptimized Lazy Loading (N+1 query problem).
     */
    public function show(Request $request, int $id): View
    {
        $mode = $request->query('mode', 'optimized');

        DB::enableQueryLog();
        DB::flushQueryLog();
        $startTime = microtime(true);

        if ($mode === 'lazy') {
            // UNOPTIMIZED QUERY: Intentionally demonstrates the N+1 Query Problem
            $chatSession = ChatSession::findOrFail($id);

            // Iterating over relations causes N+1 SQL queries to be executed on the fly
            foreach ($chatSession->chatMessages as $message) {
                foreach ($message->toolExecutionLogs as $toolLog) {
                    $agent = $toolLog->loggable;
                    $agentName = $agent?->name;
                }
            }
        } else {
            // OPTIMIZED QUERY: Nested Eager Loading with() bertingkat
            // Solves the N+1 problem completely in a constant, minimal number of SQL queries.
            $chatSession = ChatSession::with([
                'user',
                'chatMessages' => function ($query) {
                    $query->orderBy('sequence_number', 'asc')->orderBy('created_at', 'asc');
                },
                'chatMessages.toolExecutionLogs.loggable',
            ])->findOrFail($id);
        }

        $executionTimeMs = round((microtime(true) - $startTime) * 1000, 2);
        $queries = DB::getQueryLog();
        $queryCount = count($queries);

        return view('chat.show', compact('chatSession', 'queries', 'queryCount', 'executionTimeMs', 'mode'));
    }

    /**
     * Create a new chat session.
     */
    public function store(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'agent_mode' => 'required|string|in:autonomous_investigation,guided_secops_copilot,strict_compliance_audit,triage_and_containment',
        ]);

        $userId = Auth::id() ?? 1;

        $session = ChatSession::create([
            'user_id' => $userId,
            'title' => $validated['title'],
            'session_uuid' => (string) Str::uuid(),
            'status' => 'active',
            'agent_mode' => $validated['agent_mode'],
        ]);

        // Add initial system message
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'system',
            'content' => "Agentic AI session initialized in [{$validated['agent_mode']}] mode. Ready for security investigations.",
            'token_count' => 35,
            'sequence_number' => 1,
        ]);

        return redirect()->route('chat.show', $session->id)
            ->with('status', 'Chat session created successfully!');
    }

    /**
     * Send a message and simulate automated agent tool execution.
     */
    public function sendMessage(Request $request, int $id): RedirectResponse
    {
        $validated = $request->validate([
            'content' => 'required|string|min:3',
        ]);

        $session = ChatSession::findOrFail($id);
        $nextSeq = $session->chatMessages()->max('sequence_number') + 1;

        // 1. Save User Message
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => $validated['content'],
            'token_count' => (int) (strlen($validated['content']) / 3),
            'sequence_number' => $nextSeq++,
        ]);

        // 2. Simulate Agentic Assistant Response & Tool Execution
        $lowerContent = strtolower($validated['content']);
        $assistantContent = '';
        $toolName = '';
        $agent = null;
        $inputParams = [];
        $outputPayload = [];

        if (str_contains($lowerContent, 'port') || str_contains($lowerContent, 'scan') || str_contains($lowerContent, 'network')) {
            $agent = SecurityScanner::first() ?? SecurityScanner::factory()->create();
            $assistantContent = "Initiating port sweep and security surface mapping via [{$agent->name}].";
            $toolName = 'nmap_stealth_recon';
            $inputParams = ['target' => '192.168.1.0/24', 'ports' => '22,80,443,8080', 'flags' => '-sV -T4'];
            $outputPayload = ['hosts_discovered' => 2, 'open_services' => ['80/http Apache', '22/ssh OpenSSH'], 'risk' => 'medium'];
        } elseif (str_contains($lowerContent, 'malware') || str_contains($lowerContent, 'file') || str_contains($lowerContent, 'virus') || str_contains($lowerContent, 'hash')) {
            $agent = MalwareScanner::first() ?? MalwareScanner::factory()->create();
            $assistantContent = "Submitting binary sample to [{$agent->name}] for static bytecode and heuristic signature checking.";
            $toolName = 'yara_clamav_analyzer';
            $inputParams = ['file_path' => '/var/quarantine/sample.bin', 'heuristic_level' => 'aggressive'];
            $outputPayload = ['verdict' => 'SUSPICIOUS', 'matches' => ['Trojan.Script.Heuristic'], 'confidence_score' => 0.91];
        } else {
            $agent = LogAnalyzer::first() ?? LogAnalyzer::factory()->create();
            $assistantContent = "Extracting telemetry and parsing log patterns using [{$agent->name}].";
            $toolName = 'owasp_pattern_correlator';
            $inputParams = ['source' => 'system_logs', 'ruleset' => 'owasp_crs_v4', 'timeframe' => 'last_1h'];
            $outputPayload = ['anomalies_detected' => 7, 'injection_attempts' => 2, 'status' => 'quarantined'];
        }

        $assistantMessage = ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'assistant',
            'content' => $assistantContent.' Tool execution completed.',
            'token_count' => 120,
            'sequence_number' => $nextSeq,
        ]);

        // 3. Create Polymorphic ToolExecutionLog
        ToolExecutionLog::create([
            'chat_message_id' => $assistantMessage->id,
            'tool_name' => $toolName,
            'status' => 'success',
            'input_parameters' => $inputParams,
            'output_payload' => $outputPayload,
            'execution_time_ms' => rand(180, 890),
            'loggable_type' => get_class($agent),
            'loggable_id' => $agent->id,
        ]);

        return redirect()->route('chat.show', $session->id)
            ->with('status', 'Message sent and agent tool executed successfully!');
    }
}
