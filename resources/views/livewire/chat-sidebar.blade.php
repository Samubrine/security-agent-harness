<aside class="chat-sidebar" aria-label="Investigation sessions list">
    <div class="sidebar-header">
        <div class="sidebar-title-wrap">
            <span class="eyebrow">Investigations</span>
            <h2 class="sidebar-heading">Conversations</h2>
        </div>
        <button type="button" wire:click="openNewModal" class="button primary small" title="Start new session">
            <svg class="icon icon-plus" aria-hidden="true" style="width:14px;height:14px;margin-right:4px;"><use href="#i-plus"/></svg>
            <span>New</span>
        </button>
    </div>

    <div class="sidebar-list" role="list">
        @forelse ($sessions as $session)
            @php
                $isActive = ($activeSessionId === $session->id);
                $modeShort = match($session->agent_mode) {
                    'autonomous_investigation' => 'Autonomous',
                    'guided_secops_copilot' => 'Copilot',
                    'strict_compliance_audit' => 'Audit',
                    'triage_and_containment' => 'Triage',
                    default => 'Agent',
                };
            @endphp
            <div 
                wire:key="session-{{ $session->id }}" 
                wire:click="selectSession({{ $session->id }})"
                class="session-item {{ $isActive ? 'is-active' : '' }}" 
                role="button" 
                tabindex="0"
                aria-current="{{ $isActive ? 'true' : 'false' }}"
                @keydown.enter="selectSession({{ $session->id }})"
            >
                <div class="session-item-header">
                    <span class="session-dot {{ $isActive ? 'dot-active' : '' }}" aria-hidden="true"></span>
                    <strong class="session-title" title="{{ $session->title }}">{{ $session->title }}</strong>
                </div>
                <div class="session-meta">
                    <span class="session-badge">{{ $modeShort }}</span>
                    <span class="session-count">{{ $session->chat_messages_count }} {{ \Illuminate\Support\Str::plural('msg', $session->chat_messages_count) }}</span>
                    <span class="session-time">{{ $session->updated_at->diffForHumans(null, true) }}</span>
                </div>
            </div>
        @empty
            <div class="sidebar-empty">
                <p class="empty-note">Belum ada riwayat sesi.</p>
                <button type="button" wire:click="openNewModal" class="button secondary small">Mulai Percakapan</button>
            </div>
        @endforelse
    </div>

    {{-- New Session Modal --}}
    @if ($showModal)
        <div class="modal-backdrop" wire:keydown.escape="closeModal" tabindex="0">
            <div class="modal-panel" role="dialog" aria-modal="true" aria-labelledby="modal-title">
                <div class="modal-header">
                    <div>
                        <span class="eyebrow">New Session</span>
                        <h3 id="modal-title">Start Security Investigation</h3>
                    </div>
                    <button type="button" wire:click="closeModal" class="icon-btn" aria-label="Close dialog">
                        <svg class="icon" aria-hidden="true"><use href="#i-close"/></svg>
                    </button>
                </div>

                <form wire:submit="createSession" class="modal-form">
                    <div class="form-group">
                        <label for="newTitle" class="form-label">Objective / Title</label>
                        <input 
                            type="text" 
                            id="newTitle" 
                            wire:model="newTitle" 
                            class="form-input" 
                            placeholder="e.g. Audit Nginx web01 for CVE vulnerabilities" 
                            autofocus
                        >
                        @error('newTitle') <span class="form-error">{{ $message }}</span> @enderror
                    </div>

                    <div class="form-group">
                        <label for="newAgentMode" class="form-label">Operating Agent Mode</label>
                        <select id="newAgentMode" wire:model="newAgentMode" class="form-select">
                            <option value="autonomous_investigation">Autonomous investigation (Chains tools independently)</option>
                            <option value="guided_secops_copilot">Guided SecOps copilot (Explains findings in plain language)</option>
                            <option value="strict_compliance_audit">Strict compliance audit (Formal CWE mapping)</option>
                            <option value="triage_and_containment">Triage & containment (Prioritises exploited threats)</option>
                        </select>
                        @error('newAgentMode') <span class="form-error">{{ $message }}</span> @enderror
                    </div>

                    <div class="modal-actions">
                        <button type="button" wire:click="closeModal" class="button secondary">Batal</button>
                        <button type="submit" wire:loading.attr="disabled" class="button primary">
                            <span wire:loading.remove>Buat Sesi</span>
                            <span wire:loading>Membuat...</span>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    @endif
</aside>
