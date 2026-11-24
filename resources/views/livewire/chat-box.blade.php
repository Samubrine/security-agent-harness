@php
    $md = fn ($text) => \Illuminate\Support\Str::markdown((string) $text, ['html_input' => 'escape', 'allow_unsafe_links' => false]);
    $lastMsg = $messages->last();
@endphp

<main class="chat-main" aria-label="Conversation workspace">
    @if ($session)
        <header class="chat-header">
            <div class="chat-header-info">
                <div class="chat-status-indicator">
                    <span class="status-pulse-dot" aria-hidden="true"></span>
                    <span class="eyebrow">{{ strtoupper(str_replace('_', ' ', $session->agent_mode)) }}</span>
                </div>
                <h1 class="chat-title">{{ $session->title }}</h1>
                <p class="chat-subtitle">
                    Dibuat {{ $session->created_at->format('d M Y, H:i') }} · Status: <span class="badge-status">{{ ucfirst($session->status) }}</span>
                </p>
            </div>
            <div class="chat-header-actions">
                <span class="token-summary" title="Pesan dalam sesi ini">{{ $messages->count() }} pesan</span>
            </div>
        </header>

        <section class="chat-thread-container" aria-label="Thread obrolan">
            <div class="chat-thread" id="chat-thread-scroll">
                @forelse ($messages as $msg)
                    @php $isLast = ($msg->id === $lastMsg?->id); @endphp

                    @if ($msg->role === 'system')
                        <div class="msg-row msg-system-row" wire:key="msg-{{ $msg->id }}">
                            <div class="msg-bubble-system">
                                <span class="system-icon" aria-hidden="true"><svg class="icon"><use href="#i-shield"/></svg></span>
                                <span>{{ $msg->content }}</span>
                            </div>
                        </div>

                    @elseif ($msg->role === 'user')
                        <div class="msg-row msg-user-row" wire:key="msg-{{ $msg->id }}">
                            <div class="msg-bubble-user">
                                <div class="msg-user-meta">
                                    <span class="sender-name">{{ auth()->user()->name }}</span>
                                    <time class="msg-timestamp">{{ $msg->created_at->format('H:i') }}</time>
                                </div>
                                <div class="msg-user-text">{{ $msg->content }}</div>
                            </div>
                        </div>

                    @else
                        {{-- Assistant Role --}}
                        <div class="msg-row msg-assistant-row" wire:key="msg-{{ $msg->id }}">
                            <article class="msg-bubble-assistant">
                                <div class="msg-assistant-meta">
                                    <strong class="assistant-name">AEGIS Security Agent</strong>
                                    <time class="msg-timestamp">{{ $msg->created_at->format('H:i') }}</time>
                                    @if ($msg->token_count > 0)
                                        <span class="badge">{{ number_format($msg->token_count) }} tokens</span>
                                    @endif
                                    @if ($msg->toolExecutionLogs->isNotEmpty())
                                        <span class="badge tool-badge">{{ $msg->toolExecutionLogs->count() }} tool {{ \Illuminate\Support\Str::plural('run', $msg->toolExecutionLogs->count()) }}</span>
                                    @endif
                                </div>

                                {{-- Tool Execution Logs (Polymorphic Relation) --}}
                                @if ($msg->toolExecutionLogs->isNotEmpty())
                                    <div class="steps">
                                        <div class="steps-title"><span>What the agent did</span><span>tool_execution_logs</span></div>
                                        @foreach ($msg->toolExecutionLogs->sortBy('id') as $toolLog)
                                            @include('chat.partials.tool-log', ['toolLog' => $toolLog])
                                        @endforeach
                                    </div>
                                @endif

                                {{-- Reasoning Disclosure --}}
                                @if ($msg->reasoning)
                                    <details class="reasoning-box">
                                        <summary class="reasoning-summary">Log Penalaran Asisten (Reasoning)</summary>
                                        <div class="reasoning-content markdown-body">{!! $md($msg->reasoning) !!}</div>
                                    </details>
                                @endif

                                {{-- Challenge 1: Typewriter Simulation for Latest Assistant Message --}}
                                @if ($isLast && $msg->role === 'assistant')
                                    <div 
                                        x-data="{
                                            rawText: @js($msg->content),
                                            rendered: '',
                                            typing: true,
                                            init() {
                                                if (window.__lastAnimatedMsg === {{ $msg->id }}) {
                                                    this.rendered = this.rawText;
                                                    this.typing = false;
                                                    return;
                                                }
                                                window.__lastAnimatedMsg = {{ $msg->id }};
                                                let i = 0;
                                                const speed = 6;
                                                const interval = setInterval(() => {
                                                    i += 5;
                                                    this.rendered = this.rawText.slice(0, i);
                                                    if (i >= this.rawText.length) {
                                                        this.rendered = this.rawText;
                                                        this.typing = false;
                                                        clearInterval(interval);
                                                    }
                                                }, speed);
                                            }
                                        }"
                                        class="assistant-content markdown-body"
                                    >
                                        <template x-if="typing">
                                            <div class="typewriter-stream">
                                                <pre class="typewriter-text" x-text="rendered"></pre>
                                                <span class="typewriter-cursor">▋</span>
                                            </div>
                                        </template>
                                        <template x-if="!typing">
                                            <div>{!! $md($msg->content) !!}</div>
                                        </template>
                                    </div>
                                @else
                                    <div class="assistant-content markdown-body">
                                        {!! $md($msg->content) !!}
                                    </div>
                                @endif

                                {{-- Fact Check / Claim Check --}}
                                @include('chat.partials.fact-check', ['check' => $msg->claim_check])

                                {{-- Pending Actions Approval --}}
                                @if (is_array($msg->pending_action))
                                    @include('chat.partials.pending-action', ['action' => $msg->pending_action, 'message' => $msg, 'isLatest' => $isLast])
                                @endif
                            </article>
                        </div>
                    @endif
                @empty
                    <div class="chat-empty-thread">
                        <div class="empty-icon-wrap" aria-hidden="true">
                            <svg class="icon"><use href="#i-shield"/></svg>
                        </div>
                        <h3>Mulai Investigasi Keamanan</h3>
                        <p>Ketik instruksi prompt di bawah, misalnya: <em>"Cek apakah server Apache rentan terhadap CVE terbaru"</em> atau <em>"Lakukan pemindaian port lokal"</em>.</p>
                    </div>
                @endforelse
            </div>
        </section>

        {{-- Prompt Composer Area --}}
        <footer class="chat-composer-area">
            {{-- Loading State Overlay (Slide 13) --}}
            <div wire:loading.flex class="composer-loading-notice">
                <span class="inline-spinner" aria-hidden="true"></span>
                <span class="loading-text">Server AI sedang memproses instruksi dan mengeksekusi tools...</span>
            </div>

            {{-- Interactive Demo Prompt Chips for Quick Presentation & Testing --}}
            <div class="demo-chips-bar">
                <span class="demo-label">Demo Cepat:</span>
                <button type="button" class="demo-chip" wire:click="$set('prompt', 'Buatkan skrip Python audit scanner untuk memindai port terbuka dan mendeteksi servis lab.')">
                    ⚡ 1. Scan Port (Python)
                </button>
                <button type="button" class="demo-chip" wire:click="$set('prompt', 'Tuliskan skrip bash otomatisasi hardening konfigurasi Nginx untuk mitigasi CVE-2021-23017.')">
                    🛡️ 2. Hardening Patch (Bash)
                </button>
                <button type="button" class="demo-chip" wire:click="$set('prompt', 'Jalankan analisis log autentikasi lab-logs dan berikan laporan keamanan.')">
                    🔍 3. Analisis Log (Audit)
                </button>
            </div>

            <form wire:submit="kirim" class="composer-form">
                <div class="input-container">
                    <textarea 
                        wire:model.live.debounce.150ms="prompt" 
                        class="composer-textarea" 
                        placeholder="Tulis instruksi keamanan Anda (tekan Ctrl+Enter atau klik Kirim)..." 
                        rows="2"
                        @keydown.ctrl.enter="$wire.kirim()"
                        wire:loading.attr="disabled"
                    ></textarea>

                    <div class="composer-meta-bar">
                        {{-- Character Counter & Validation (Slide 24 & 30) --}}
                        <div class="char-counter-wrap">
                            <span class="char-count {{ $remainingChars < 0 ? 'text-critical' : ($remainingChars < 100 ? 'text-warning' : 'text-muted') }}">
                                Sisa Karakter: <strong>{{ $remainingChars }}</strong> / 1000
                            </span>
                            @error('prompt')
                                <span class="error-inline">{{ $message }}</span>
                            @enderror
                        </div>

                        {{-- Submit Button with wire:loading Protection (Slide 13, 29, 35) --}}
                        <button 
                            type="submit" 
                            wire:loading.attr="disabled"
                            class="button primary submit-btn"
                            @if ($remainingChars < 0) disabled @endif
                        >
                            <span wire:loading.remove>
                                <svg class="icon icon-send" aria-hidden="true" style="width:14px;height:14px;margin-right:6px;"><use href="#i-arrow-right"/></svg>
                                Kirim Instruksi
                            </span>
                            <span wire:loading class="btn-spinner-state">
                                <span class="inline-spinner" aria-hidden="true"></span>
                                Memproses...
                            </span>
                        </button>
                    </div>
                </div>
            </form>
        </footer>

    @else
        <div class="no-session-selected">
            <div class="empty-notice-box">
                <svg class="icon large-icon" aria-hidden="true"><use href="#i-shield"/></svg>
                <h2>Tidak Ada Sesi yang Dipilih</h2>
                <p>Silakan pilih percakapan dari daftar di sebelah kiri, atau buat sesi investigasi baru untuk mulai mengobrol dengan asisten AI.</p>
            </div>
        </div>
    @endif
</main>
