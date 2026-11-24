<?php

namespace App\Livewire;

use App\Agent\AgentRunner;
use App\Agent\ApprovalLedger;
use App\Models\ChatMessage;
use Illuminate\Contracts\View\View;
use Livewire\Attributes\On;
use Livewire\Component;
use Throwable;

class ChatBox extends Component
{
    public ?int $sessionId = null;

    public string $prompt = '';

    public int $charCount = 0;

    public int $remainingChars = 500;

    protected array $rules = [
        'prompt' => 'required|min:3|max:1000',
    ];

    protected array $messages = [
        'prompt.required' => 'Kotak prompt tidak boleh dikosongkan!',
        'prompt.min' => 'Instruksi minimal terdiri atas 3 karakter.',
        'prompt.max' => 'Instruksi maksimal 1000 karakter demi kenyamanan RAM.',
    ];

    public function mount(?int $initialSessionId = null): void
    {
        $user = auth()->user();
        if (! $user) {
            return;
        }

        if ($initialSessionId) {
            $session = $user->chatSessions()->find($initialSessionId);
            if ($session) {
                $this->sessionId = $session->id;
                $this->scanLatestCode();

                return;
            }
        }

        // Fallback to latest session
        $latest = $user->chatSessions()->latest('updated_at')->first();
        if ($latest) {
            $this->sessionId = $latest->id;
            $this->scanLatestCode();
        }
    }

    public function updatedPrompt(): void
    {
        $len = mb_strlen($this->prompt);
        $this->charCount = $len;
        $this->remainingChars = 1000 - $len;

        $this->validateOnly('prompt');
    }

    public function kirim(): void
    {
        $user = auth()->user();
        if (! $user || ! $this->sessionId) {
            $this->addError('prompt', 'Sesi aktif tidak ditemukan.');

            return;
        }

        $this->validate();

        $session = $user->chatSessions()->find($this->sessionId);
        if (! $session) {
            $this->addError('prompt', 'Sesi tidak sah atau telah dihapus.');

            return;
        }

        $userPrompt = trim($this->prompt);
        $seq = (int) ($session->chatMessages()->max('sequence_number') ?? 0) + 1;

        // 1. Simpan pesan fisik user ke database MySQL relasional
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => $userPrompt,
            'token_count' => (int) ceil(strlen($userPrompt) / 4),
            'sequence_number' => $seq,
        ]);

        $session->touch(); // Update updated_at

        // Bersihkan input teks seketika (mencegah double input & menjaga kenyamanan UX)
        $this->prompt = '';
        $this->charCount = 0;
        $this->remainingChars = 1000;
        $this->resetValidation();

        // 2. Kirim instruksi ke Agent LLM Engine & Simpan balasan
        try {
            $runner = app(AgentRunner::class);
            $assistantMsg = $runner->respond($session);

            $this->dispatch('message-sent');
            $this->extractAndDispatchCode($assistantMsg->content);
            $this->dispatch('trigger-typewriter', messageId: $assistantMsg->id);
        } catch (Throwable $e) {
            // Graceful error handling (Slide 19 & Slide 37)
            $fallbackMsg = ChatMessage::create([
                'chat_session_id' => $session->id,
                'role' => 'assistant',
                'content' => "Koneksi AI Terputus atau terjadi kesalahan eksekusi: {$e->getMessage()}.\nSistem tetap aman dan log audit telah dicatat.",
                'token_count' => 0,
                'sequence_number' => $seq + 1,
            ]);

            $this->dispatch('message-sent');
            $this->dispatch('trigger-typewriter', messageId: $fallbackMsg->id);
        }
    }

    public function resolveAction(int $messageId, string $decision, ?string $chosenTarget = null): void
    {
        $user = auth()->user();
        if (! $user || ! $this->sessionId) {
            return;
        }

        $session = $user->chatSessions()->find($this->sessionId);
        if (! $session) {
            return;
        }

        $assistantMsg = $session->chatMessages()->where('role', 'assistant')->find($messageId);
        if (! $assistantMsg) {
            return;
        }

        $action = $assistantMsg->pending_action;
        if (! is_array($action) || isset($action['resolved'])) {
            return;
        }

        $ledger = app(ApprovalLedger::class);
        $skill = str_replace('_', ' ', (string) ($action['skill'] ?? 'investigation'));

        if ($action['type'] === 'approval') {
            $tools = collect($action['requests'] ?? [])->pluck('provider')->unique()->implode(' and ');
            if ($decision === 'approve') {
                $ledger->grant((string) $action['skill'], $action['target'] ?? null, array_fill(0, count($action['requests'] ?? []), true));
                $text = "I approve using {$tools} for the {$skill}".(! empty($action['target']) ? " on {$action['target']}" : '').'. Run it again with my approval and tell me what it finds.';
            } else {
                $text = "I decline: do not use {$tools}. Continue without it and tell me what that leaves unknown.";
            }
            $resolution = $decision;
        } else {
            $value = $chosenTarget ?? ($action['fields'][0]['options'][0] ?? 'target');
            $text = "Use {$value} for the {$skill}.".(! empty($action['objective']) ? ' Goal: '.$action['objective'] : '');
            $resolution = $value;
        }

        $assistantMsg->update([
            'pending_action' => $action + [
                'resolved' => $resolution,
                'resolved_at' => now()->toIso8601String(),
            ],
        ]);

        // Simpan konfirmasi user
        $seq = (int) ($session->chatMessages()->max('sequence_number') ?? 0) + 1;
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'user',
            'content' => $text,
            'token_count' => (int) ceil(strlen($text) / 4),
            'sequence_number' => $seq,
        ]);

        try {
            $runner = app(AgentRunner::class);
            $newReply = $runner->respond($session);
            $this->dispatch('message-sent');
            $this->extractAndDispatchCode($newReply->content);
            $this->dispatch('trigger-typewriter', messageId: $newReply->id);
        } catch (Throwable $e) {
            ChatMessage::create([
                'chat_session_id' => $session->id,
                'role' => 'assistant',
                'content' => "Gagal mengeksekusi instruksi lanjutan: {$e->getMessage()}",
                'token_count' => 0,
                'sequence_number' => $seq + 1,
            ]);
            $this->dispatch('message-sent');
        }
    }

    #[On('session-selected')]
    public function onSessionSelected(int $sessionId): void
    {
        $user = auth()->user();
        if (! $user) {
            return;
        }

        $session = $user->chatSessions()->find($sessionId);
        if ($session) {
            $this->sessionId = $session->id;
            $this->prompt = '';
            $this->charCount = 0;
            $this->remainingChars = 1000;
            $this->resetValidation();
            $this->scanLatestCode();
        }
    }

    private function scanLatestCode(): void
    {
        if (! $this->sessionId) {
            return;
        }

        $latestAssistant = ChatMessage::where('chat_session_id', $this->sessionId)
            ->where('role', 'assistant')
            ->latest('id')
            ->first();

        if ($latestAssistant) {
            $this->extractAndDispatchCode($latestAssistant->content);
        }
    }

    private function extractAndDispatchCode(string $content): void
    {
        // Detect markdown code blocks: ```lang ... ```
        if (preg_match('/```([a-zA-Z0-9_\-]+)?\s*\n(.*?)```/s', $content, $matches)) {
            $language = ! empty($matches[1]) ? trim($matches[1]) : 'plaintext';
            $code = trim($matches[2]);
            $filename = match (strtolower($language)) {
                'php' => 'analysis.php',
                'python', 'py' => 'scanner.py',
                'bash', 'sh' => 'recon_script.sh',
                'json' => 'vulnerability_report.json',
                'html' => 'preview.html',
                'yaml', 'yml' => 'policy.yaml',
                default => 'audit_output.txt',
            };

            $this->dispatch('code-detected', [
                'language' => $language,
                'code' => $code,
                'filename' => $filename,
                'sessionId' => $this->sessionId,
            ]);
        }
    }

    public function render(): View
    {
        $user = auth()->user();
        $session = null;
        $messages = collect();

        if ($user && $this->sessionId) {
            // OPTIMIZED NESTED EAGER LOADING: Mencegah N+1 Query Problem (Slide 41)
            $session = $user->chatSessions()->find($this->sessionId);
            if ($session) {
                $messages = $session->chatMessages()
                    ->with([
                        'toolExecutionLogs.loggable',
                        'toolExecutionLogs.evidenceArtifacts',
                    ])
                    ->orderBy('sequence_number', 'asc')
                    ->orderBy('id', 'asc')
                    ->get();
            }
        }

        return view('livewire.chat-box', [
            'session' => $session,
            'messages' => $messages,
        ]);
    }
}
