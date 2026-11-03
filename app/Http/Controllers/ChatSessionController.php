<?php

namespace App\Http\Controllers;

use App\Agent\AgentRunner;
use App\Agent\ApprovalLedger;
use App\Agent\Harness\RunArchive;
use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\ToolExecutionLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
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
            ->paginate(12);

        $ownLogs = ToolExecutionLog::whereHas('chatMessage.chatSession', fn ($q) => $q->whereBelongsTo($request->user()));
        $toolCalls = (clone $ownLogs)->count();

        // Polymorphic breakdown: which kind of agent/knowledge source handled the calls.
        $byOwner = (clone $ownLogs)
            ->selectRaw('loggable_type, count(*) as total')
            ->groupBy('loggable_type')
            ->pluck('total', 'loggable_type');

        $investigations = count($archive->records());

        return view('chat.index', compact('chatSessions', 'toolCalls', 'byOwner', 'investigations'));
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
                'chatMessages.toolExecutionLogs.evidenceArtifacts',
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
    public function sendMessage(Request $request, int $id, AgentRunner $agent): Response
    {
        $validated = $request->validate([
            'content' => 'required|string|min:2|max:4000',
        ]);

        $session = $this->ownedSession($request, $id);
        $this->addUserMessage($session, $validated['content']);

        return $this->answer($request, $session, $agent);
    }

    /**
     * The operator answers what the agent was waiting for: approve or decline a harness step, or
     * supply missing context (which machine?). The answer becomes a chat message, so the agent
     * (and anyone reading the conversation later) sees exactly what was decided.
     */
    public function resolveAction(Request $request, int $id, int $message, AgentRunner $agent, ApprovalLedger $ledger): Response
    {
        $session = $this->ownedSession($request, $id);
        $assistant = $session->chatMessages()->where('role', 'assistant')->findOrFail($message);
        $action = $assistant->pending_action;
        if (! is_array($action) || isset($action['resolved'])) {
            return redirect()->to(route('chat.show', $session->id).'#latest')->with('error', 'That question has already been answered.');
        }

        $skill = str_replace('_', ' ', (string) ($action['skill'] ?? 'investigation'));
        if ($action['type'] === 'approval') {
            $decision = $request->validate(['decision' => 'required|in:approve,decline'])['decision'];
            $tools = collect($action['requests'] ?? [])->pluck('provider')->unique()->implode(' and ');
            if ($decision === 'approve') {
                // One "yes" per request the operator saw; anything new in the rerun is still declined.
                $ledger->grant((string) $action['skill'], $action['target'] ?? null, array_fill(0, count($action['requests'] ?? []), true));
                $text = "I approve using {$tools} for the {$skill}".(! empty($action['target']) ? " on {$action['target']}" : '').'. Run it again with my approval and tell me what it finds.';
            } else {
                $text = "I decline: do not use {$tools}. Continue without it and tell me what that leaves unknown.";
            }
            $resolution = $decision;
        } else {
            $field = $action['fields'][0] ?? ['name' => 'target', 'options' => []];
            $value = $request->validate([$field['name'] => ['required', 'string', 'in:'.implode(',', $field['options'])]])[$field['name']];
            $text = "Use {$value} for the {$skill}.".(! empty($action['objective']) ? ' Goal: '.$action['objective'] : '');
            $resolution = $value;
        }

        $assistant->update(['pending_action' => $action + ['resolved' => $resolution, 'resolved_at' => now()->toIso8601String()]]);
        $this->addUserMessage($session, $text);

        return $this->answer($request, $session, $agent);
    }

    private function addUserMessage(ChatSession $session, string $content): void
    {
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => $content,
            'token_count' => (int) ceil(mb_strlen($content) / 4),
            'sequence_number' => (int) $session->chatMessages()->max('sequence_number') + 1,
        ]);
    }

    /**
     * Run the agent. A browser that asks for NDJSON gets every step as it happens (one JSON object
     * per line); anything else waits and is redirected to the conversation. Streaming the same
     * response, rather than polling a second URL, is what makes live progress work on the
     * single-threaded `php artisan serve`.
     */
    private function answer(Request $request, ChatSession $session, AgentRunner $agent): Response
    {
        // An investigation plus several LLM turns can take a minute or two.
        set_time_limit(2 * (int) config('agent.harness.timeout') + 6 * (int) config('agent.llm.timeout'));

        if (! str_contains((string) $request->header('Accept'), 'application/x-ndjson')) {
            $agent->respond($session);
            // Touch the session so the most recently used conversation is listed first.
            $session->touch();

            return redirect()->to(route('chat.show', $session->id).'#latest');
        }

        return response()->stream(function () use ($session, $agent) {
            ignore_user_abort(true); // closing the tab must not leave a half-written reply
            if (! app()->runningUnitTests()) {
                while (ob_get_level() > 0) {
                    ob_end_flush();
                }
            }
            $send = function (array $event): void {
                echo json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
                if (! app()->runningUnitTests()) {
                    flush();
                }
            };
            $send(['type' => 'started']);
            try {
                $reply = $agent->respond($session, $send);
                $session->touch();
                $send(['type' => 'done', 'url' => route('chat.show', ['id' => $session->id, 'reply' => $reply->id]).'#latest']);
            } catch (Throwable $e) {
                report($e);
                $send(['type' => 'error', 'message' => 'The agent stopped with an error: '.Str::limit($e->getMessage(), 200)]);
            }
        }, 200, [
            'Content-Type' => 'application/x-ndjson; charset=utf-8',
            'Cache-Control' => 'no-cache, no-transform',
            'X-Accel-Buffering' => 'no',
        ]);
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
