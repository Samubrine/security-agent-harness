<?php

namespace App\Http\Controllers;

use App\Agent\AgentRunner;
use App\Agent\Harness\RunArchive;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\ToolExecutionLog;
use App\Support\Plain;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;

class ChatSessionController extends Controller
{
    /**
     * The operator's conversations, plus what the agent has done across them.
     */
    public function index(Request $request, RunArchive $archive): View
    {
        $chatSessions = $request->user()->chatSessions()
            ->withCount(['chatMessages'])
            ->latest('updated_at')
            ->paginate(8);

        $ownLogs = ToolExecutionLog::whereHas('chatMessage.chatSession', fn ($q) => $q->whereBelongsTo($request->user()));
        $toolCalls = (clone $ownLogs)->count();

        // Polymorphic breakdown: which kind of agent/knowledge source handled the calls.
        $byOwner = (clone $ownLogs)
            ->selectRaw('loggable_type, count(*) as total')
            ->groupBy('loggable_type')
            ->pluck('total', 'loggable_type');

        $investigations = count($archive->records());
        $stoppedCalls = (clone $ownLogs)->where('status', '!=', 'success')->count();
        $recentLogs = (clone $ownLogs)->with('loggable')->latest('id')->limit(6)->get();
        $posture = $this->posture($archive);
        $verdict = Plain::verdict($posture['counts'], $posture['checked']);
        $scope = $this->scopeAliases();

        return view('chat.index', compact('chatSessions', 'toolCalls', 'stoppedCalls', 'byOwner', 'investigations', 'recentLogs', 'posture', 'verdict', 'scope'));
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

        return redirect()->route('chat.show', $session->id);
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

        $agent->respond($session);
        // Touch the session so the most recently used conversation is listed first.
        $session->touch();

        return redirect()->to(route('chat.show', $session->id).'#latest');
    }

    /**
     * Start a conversation straight from a question typed on the home page.
     */
    public function ask(Request $request, AgentRunner $agent): RedirectResponse
    {
        $validated = $request->validate([
            'content' => 'required|string|min:2|max:4000',
            'agent_mode' => 'nullable|string|in:autonomous_investigation,guided_secops_copilot,strict_compliance_audit,triage_and_containment',
        ]);

        return $this->startAndAnswer($request, $agent, $validated['content'], Str::limit($validated['content'], 60), $validated['agent_mode'] ?? 'autonomous_investigation');
    }

    /**
     * One click, no question: the agent decides what to check across the whole authorised scope
     * and writes the briefing itself.
     */
    public function checkup(Request $request, AgentRunner $agent): RedirectResponse
    {
        return $this->startAndAnswer(
            $request,
            $agent,
            'Run a full security check-up. Investigate every machine and log source in the authorised scope, look up the most serious flaws you find in the public vulnerability database, then give me a plain-language briefing: how safe are we, what is most urgent, and what should I fix first?',
            'Full lab check-up, '.now()->format('d M H:i'),
            'autonomous_investigation',
        );
    }

    private function startAndAnswer(Request $request, AgentRunner $agent, string $message, string $title, string $mode): RedirectResponse
    {
        $session = ChatSession::create([
            'user_id' => $request->user()->id,
            'title' => $title,
            'session_uuid' => (string) Str::uuid(),
            'status' => 'active',
            'agent_mode' => $mode,
        ]);
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'system',
            'content' => "Agentic AI session initialized in [{$mode}] mode. Ready for security investigations.",
            'token_count' => 0,
            'sequence_number' => 1,
        ]);
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => $message,
            'token_count' => (int) ceil(mb_strlen($message) / 4),
            'sequence_number' => 2,
        ]);

        set_time_limit((int) config('agent.harness.timeout') + 6 * (int) config('agent.llm.timeout'));
        $agent->respond($session);

        return redirect()->to(route('chat.show', $session->id).'#latest');
    }

    /**
     * Where the lab stands, from the newest investigation of each kind.
     *
     * @return array{checked: bool, counts: array<string, int>, problems: list<array<string, mixed>>, runs: list<array<string, mixed>>}
     */
    private function posture(RunArchive $archive): array
    {
        $latest = [];
        foreach ($archive->list(40) as $run) {
            $latest[$run['skill'] ?? '?'] ??= $run;
        }

        $problems = [];
        foreach ($latest as $run) {
            try {
                foreach ($archive->summary($run['run_id'])['findings'] as $finding) {
                    $problems[] = $finding + ['run_id' => $run['run_id'], 'skill' => $run['skill']];
                }
            } catch (\Throwable) {
                // An unreadable run is skipped; the home page must always render.
            }
        }
        $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($problems, fn ($a, $b) => ($rank[$a['severity'] ?? 'info'] ?? 9) <=> ($rank[$b['severity'] ?? 'info'] ?? 9));

        return [
            'checked' => $latest !== [],
            'counts' => collect($problems)->countBy(fn ($f) => $f['severity'] ?? 'info')->all(),
            'problems' => $problems,
            'runs' => array_values($latest),
        ];
    }

    /** @return array<string, string> alias => "machine" | "log files" */
    private function scopeAliases(): array
    {
        try {
            return collect(app(\App\Agent\Harness\HarnessRunner::class)->scope()->aliases)
                ->map(fn ($address) => str_starts_with($address, 'fs:') ? 'log files' : 'machine')
                ->all();
        } catch (\Throwable) {
            return [];
        }
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
