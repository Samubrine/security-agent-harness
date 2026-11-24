<?php

namespace App\Livewire;

use App\Models\ChatMessage;
use App\Models\ChatSession;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Str;
use Livewire\Attributes\On;
use Livewire\Component;

class ChatSidebar extends Component
{
    public ?int $activeSessionId = null;

    public bool $showModal = false;

    public string $newTitle = '';

    public string $newAgentMode = 'autonomous_investigation';

    protected array $rules = [
        'newTitle' => 'required|string|min:3|max:100',
        'newAgentMode' => 'required|string|in:autonomous_investigation,guided_secops_copilot,strict_compliance_audit,triage_and_containment',
    ];

    protected array $messages = [
        'newTitle.required' => 'Judul percakapan wajib diisi.',
        'newTitle.min' => 'Judul percakapan minimal terdiri dari 3 karakter.',
        'newTitle.max' => 'Judul percakapan maksimal 100 karakter.',
        'newAgentMode.required' => 'Pilih mode operasional asisten AI.',
    ];

    public function mount(?int $initialSessionId = null): void
    {
        $user = auth()->user();
        if ($initialSessionId && $user) {
            $exists = $user->chatSessions()->where('id', $initialSessionId)->exists();
            if ($exists) {
                $this->activeSessionId = $initialSessionId;

                return;
            }
        }

        // Default to latest active session if available
        if ($user) {
            $latest = $user->chatSessions()->latest('updated_at')->first();
            $this->activeSessionId = $latest?->id;
        }
    }

    public function selectSession(int $id): void
    {
        $user = auth()->user();
        if (! $user) {
            return;
        }

        $session = $user->chatSessions()->find($id);
        if ($session) {
            $this->activeSessionId = $session->id;
            $this->dispatch('session-selected', sessionId: $session->id);
        }
    }

    public function openNewModal(): void
    {
        $this->resetValidation();
        $this->newTitle = '';
        $this->newAgentMode = 'autonomous_investigation';
        $this->showModal = true;
    }

    public function closeModal(): void
    {
        $this->showModal = false;
        $this->resetValidation();
    }

    public function createSession(): void
    {
        $this->validate();

        $user = auth()->user();
        if (! $user) {
            return;
        }

        $session = ChatSession::create([
            'user_id' => $user->id,
            'title' => trim($this->newTitle),
            'session_uuid' => (string) Str::uuid(),
            'status' => 'active',
            'agent_mode' => $this->newAgentMode,
        ]);

        // Add initial system message to start the thread
        ChatMessage::create([
            'chat_session_id' => $session->id,
            'role' => 'system',
            'content' => "Agentic AI session initialized in [{$this->newAgentMode}] mode. Ready for security investigations.",
            'token_count' => 0,
            'sequence_number' => 1,
        ]);

        $this->activeSessionId = $session->id;
        $this->showModal = false;
        $this->newTitle = '';

        $this->dispatch('session-selected', sessionId: $session->id);
        $this->dispatch('session-created', sessionId: $session->id);
    }

    #[On('message-sent')]
    public function onMessageSent(): void
    {
        // Re-renders the sidebar view to update message counts & timestamps
    }

    public function render(): View
    {
        $user = auth()->user();
        $sessions = $user ? $user->chatSessions()
            ->withCount('chatMessages')
            ->latest('updated_at')
            ->get() : collect();

        return view('livewire.chat-sidebar', [
            'sessions' => $sessions,
        ]);
    }
}
