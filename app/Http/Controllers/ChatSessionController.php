<?php

namespace App\Http\Controllers;

use App\Agent\AgentRunner;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\KnowledgeSource;
use App\Models\LogAnalyzer;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;

class ChatSessionController extends Controller
{
    /**
     * Display a listing of all chat sessions.
     */
    public function index(Request $request): View
    {
        $chatSessions = $request->user()->chatSessions()
            ->with(['user'])
            ->withCount(['chatMessages'])
            ->latest()
            ->paginate(10);

        $scannersCount = SecurityScanner::count();
        $knowledgeCount = KnowledgeSource::count();
        $analyzerCount = LogAnalyzer::count();
        $totalLogsCount = ToolExecutionLog::count();

        return view('chat.index', compact(
            'chatSessions',
            'scannersCount',
            'knowledgeCount',
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
            $chatSession = $this->ownedSession($request, $id);

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
            ])->whereBelongsTo($request->user())->findOrFail($id);
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

        $session = ChatSession::create([
            'user_id' => $request->user()->id,
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
            'token_count' => 0,
            'sequence_number' => 1,
        ]);

        return redirect()->route('chat.show', $session->id)
            ->with('status', 'Chat session created successfully!');
    }

    /**
     * Send a message and let the agent answer it.
     *
     * The LLM decides which tools to call (harness investigations, findings archive, NVD); each
     * call is stored as a polymorphic ToolExecutionLog on the assistant's reply.
     */
    public function sendMessage(Request $request, int $id, AgentRunner $agent): RedirectResponse
    {
        $validated = $request->validate([
            'content' => 'required|string|min:2|max:4000',
        ]);

        $session = $this->ownedSession($request, $id);

        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => $validated['content'],
            'token_count' => (int) ceil(mb_strlen($validated['content']) / 4),
            'sequence_number' => (int) $session->chatMessages()->max('sequence_number') + 1,
        ]);

        // An investigation plus several LLM turns can take a minute or two.
        set_time_limit((int) config('agent.harness.timeout') + 6 * (int) config('agent.llm.timeout'));

        $reply = $agent->respond($session);
        $tools = $reply->toolExecutionLogs->count();

        return redirect()->route('chat.show', $session->id)
            ->with('status', $tools > 0
                ? "Agent answered after {$tools} tool call".($tools === 1 ? '' : 's').'.'
                : 'Agent answered.');
    }

    /**
     * Sessions are private to their owner: anyone else gets a 404, not a 403, so ids cannot be
     * probed.
     */
    private function ownedSession(Request $request, int $id): ChatSession
    {
        return ChatSession::whereBelongsTo($request->user())->findOrFail($id);
    }
}
