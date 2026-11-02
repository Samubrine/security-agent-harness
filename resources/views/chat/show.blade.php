<x-app-layout>
    <x-slot name="header">
        <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div class="flex items-center gap-3">
                <a href="{{ route('chat.index') }}" class="p-2 rounded-xl bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                    </svg>
                </a>
                <div>
                    <div class="flex items-center gap-2">
                        <h2 class="font-bold text-xl text-gray-900 dark:text-white leading-tight">
                            {{ $chatSession->title }}
                        </h2>
                        <span class="px-2.5 py-0.5 rounded-full text-xs font-semibold {{ $chatSession->status === 'active' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300' }}">
                            {{ ucfirst($chatSession->status) }}
                        </span>
                    </div>
                    <div class="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono">
                        <span>UUID: {{ $chatSession->session_uuid }}</span>
                        <span>•</span>
                        <span>Mode: <strong class="text-indigo-600 dark:text-indigo-400">{{ $chatSession->agent_mode }}</strong></span>
                        <span>•</span>
                        <span>Operator: {{ $chatSession->user->name ?? 'SecOps Operator' }}</span>
                    </div>
                </div>
            </div>

            <div class="flex items-center gap-2">
                <a href="{{ route('pitch.index') }}" class="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                    Slide Pitch Presentasi
                </a>
            </div>
        </div>
    </x-slot>

    <div class="py-8">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-6">

            <!-- Flash Status Message -->
            @if(session('status'))
                <div class="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 text-sm flex items-center justify-between">
                    <div class="flex items-center gap-2 font-medium">
                        <svg class="w-5 h-5 text-emerald-600" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                        </svg>
                        {{ session('status') }}
                    </div>
                </div>
            @endif

            <!-- CHALLENGE 2: Live Query Optimization & N+1 Audit Banner -->
            <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700/60 overflow-hidden">
                <div class="p-5 bg-gradient-to-r {{ $mode === 'optimized' ? 'from-emerald-950/40 via-gray-900 to-indigo-950/40 border-b border-emerald-800/30' : 'from-amber-950/40 via-gray-900 to-rose-950/40 border-b border-amber-800/30' }}">
                    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-2">
                                <span class="px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider {{ $mode === 'optimized' ? 'bg-emerald-500 text-white' : 'bg-amber-500 text-gray-900' }}">
                                    {{ $mode === 'optimized' ? 'Tantangan 2: Teroptimasi' : 'Mode N+1 Unoptimized' }}
                                </span>
                                <h3 class="text-lg font-bold text-white">
                                    {{ $mode === 'optimized' ? 'Nested Eager Loading Terbukti Bebas N+1 Query' : 'Demonstrasi Masalah N+1 Query (Lazy Loading)' }}
                                </h3>
                            </div>
                            <p class="text-xs text-gray-300 mt-1">
                                @if($mode === 'optimized')
                                    Kueri menggunakan <code class="bg-black/50 px-1.5 py-0.5 rounded text-emerald-400 font-mono">ChatSession::with(['user', 'chatMessages.toolExecutionLogs.loggable'])</code>.
                                @else
                                    Kueri memanggil relasi secara bertahap dalam perulangan tanpa <code class="bg-black/50 px-1.5 py-0.5 rounded text-amber-400 font-mono">with()</code>, memicu query berulang (N+1).
                                @endif
                            </p>
                        </div>

                        <!-- Mode Switcher Buttons -->
                        <div class="flex items-center bg-gray-900/80 p-1.5 rounded-xl border border-gray-700/60">
                            <a href="{{ route('chat.show', ['id' => $chatSession->id, 'mode' => 'optimized']) }}" class="px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all {{ $mode === 'optimized' ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30' : 'text-gray-400 hover:text-white' }}">
                                ⚡ Eager Loading
                            </a>
                            <a href="{{ route('chat.show', ['id' => $chatSession->id, 'mode' => 'lazy']) }}" class="px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all {{ $mode === 'lazy' ? 'bg-amber-600 text-white shadow-md shadow-amber-600/30' : 'text-gray-400 hover:text-white' }}">
                                ⚠️ Lazy Loading (N+1)
                            </a>
                        </div>
                    </div>

                    <!-- Metrics Badges -->
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 pt-4 border-t border-white/10">
                        <div class="bg-black/30 backdrop-blur rounded-xl p-3 border border-white/5">
                            <span class="text-xs text-gray-400 block font-medium">Total SQL Queries</span>
                            <span class="text-2xl font-extrabold {{ $mode === 'optimized' ? 'text-emerald-400' : 'text-amber-400' }} mt-0.5 block">
                                {{ $queryCount }} <span class="text-xs text-gray-400 font-normal">queries</span>
                            </span>
                        </div>
                        <div class="bg-black/30 backdrop-blur rounded-xl p-3 border border-white/5">
                            <span class="text-xs text-gray-400 block font-medium">Total Waktu Kueri</span>
                            <span class="text-2xl font-extrabold text-indigo-300 mt-0.5 block">
                                {{ $executionTimeMs }} <span class="text-xs text-gray-400 font-normal">ms</span>
                            </span>
                        </div>
                        <div class="bg-black/30 backdrop-blur rounded-xl p-3 border border-white/5">
                            <span class="text-xs text-gray-400 block font-medium">Status Masalah N+1</span>
                            <span class="text-base font-bold {{ $mode === 'optimized' ? 'text-emerald-400' : 'text-rose-400' }} mt-1 block">
                                {{ $mode === 'optimized' ? '✓ Bebas N+1 (Pass)' : '✗ Terdeteksi N+1' }}
                            </span>
                        </div>
                        <div class="bg-black/30 backdrop-blur rounded-xl p-3 border border-white/5">
                            <span class="text-xs text-gray-400 block font-medium">Inspeksi Debugbar</span>
                            <span class="text-base font-bold text-gray-200 mt-1 block">
                                Active at bottom ↘
                            </span>
                        </div>
                    </div>
                </div>

                <!-- Collapsible SQL Query Inspector -->
                <div x-data="{ open: false }" class="border-t border-gray-100 dark:border-gray-700/60 bg-gray-50/50 dark:bg-gray-800/50">
                    <button @click="open = !open" class="w-full px-5 py-3 text-left text-xs font-semibold text-gray-600 dark:text-gray-300 hover:text-indigo-600 dark:hover:text-indigo-400 flex items-center justify-between">
                        <span class="flex items-center gap-2">
                            <svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                            Inspeksi {{ $queryCount }} Kueri SQL Terjadwal (Klik untuk buka/tutup)
                        </span>
                        <svg class="w-4 h-4 transform transition-transform" :class="open ? 'rotate-180' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                    </button>
                    <div x-show="open" x-cloak class="p-5 border-t border-gray-200 dark:border-gray-700 font-mono text-xs space-y-2 bg-gray-900 text-gray-200 overflow-x-auto">
                        @foreach ($queries as $index => $q)
                            <div class="p-2.5 rounded-lg bg-gray-950/80 border border-gray-800">
                                <div class="flex items-center justify-between text-gray-400 mb-1 text-[11px]">
                                    <span class="font-bold text-indigo-400">#{{ $index + 1 }} Query ({{ $q['time'] }} ms)</span>
                                </div>
                                <div class="text-emerald-300 break-words font-semibold">{{ $q['query'] }}</div>
                                @if(!empty($q['bindings']))
                                    <div class="text-gray-500 text-[10px] mt-1">Bindings: [{{ implode(', ', array_map(fn($b) => is_numeric($b) ? $b : "'$b'", $q['bindings'])) }}]</div>
                                @endif
                            </div>
                        @endforeach
                    </div>
                </div>
            </div>

            <!-- CHAT CONVERSATION FEED -->
            <div class="space-y-4">
                @foreach ($chatSession->chatMessages as $msg)
                    @if($msg->role === 'system')
                        <!-- System Message -->
                        <div class="flex justify-center my-4">
                            <div class="px-4 py-2 rounded-xl bg-gray-200 dark:bg-gray-700/60 text-gray-700 dark:text-gray-300 text-xs font-mono flex items-center gap-2 border border-gray-300/50 dark:border-gray-600/50 shadow-sm">
                                <svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                {{ $msg->content }}
                            </div>
                        </div>
                    @elseif($msg->role === 'user')
                        <!-- User Message -->
                        <div class="flex justify-end">
                            <div class="max-w-2xl bg-gradient-to-r from-indigo-600 to-indigo-700 text-white rounded-2xl rounded-tr-sm p-4 shadow-md shadow-indigo-600/10">
                                <div class="flex items-center justify-between text-xs text-indigo-200 mb-1 gap-4">
                                    <span class="font-bold flex items-center gap-1.5">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                                        </svg>
                                        {{ $chatSession->user->name ?? 'SecOps Operator' }}
                                    </span>
                                    <span>#{{ $msg->sequence_number }} • {{ $msg->created_at->format('H:i:s') }}</span>
                                </div>
                                <p class="text-sm leading-relaxed whitespace-pre-wrap">{{ $msg->content }}</p>
                            </div>
                        </div>
                    @else
                        <!-- Assistant Message -->
                        <div class="flex justify-start">
                            <div class="max-w-3xl w-full bg-white dark:bg-gray-800 rounded-2xl rounded-tl-sm p-5 shadow-sm border border-gray-100 dark:border-gray-700/60 space-y-4">
                                <div class="flex items-center justify-between border-b border-gray-100 dark:border-gray-700 pb-2.5">
                                    <div class="flex items-center gap-2">
                                        <div class="w-7 h-7 rounded-lg bg-indigo-600 text-white flex items-center justify-center font-bold text-xs shadow-sm shadow-indigo-600/30">
                                            AI
                                        </div>
                                        <span class="font-bold text-sm text-gray-900 dark:text-white">AEGIS Autonomous Harness</span>
                                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950 text-indigo-600 dark:text-indigo-400 font-semibold">
                                            {{ $msg->token_count }} tokens
                                        </span>
                                    </div>
                                    <span class="text-xs text-gray-400 font-mono">#{{ $msg->sequence_number }} • {{ $msg->created_at->format('H:i:s') }}</span>
                                </div>

                                <p class="text-sm text-gray-800 dark:text-gray-200 leading-relaxed whitespace-pre-wrap">
                                    {{ $msg->content }}
                                </p>

                                <!-- CHALLENGE 1: Polymorphic Tool Execution Logs -->
                                @if($msg->toolExecutionLogs->isNotEmpty())
                                    <div class="space-y-3 pt-2">
                                        <div class="flex items-center gap-2">
                                            <span class="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                                                🛠️ Log Pemanggilan Alat (Polymorphic Tool Execution Logs)
                                            </span>
                                            <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 text-purple-800 dark:bg-purple-900/60 dark:text-purple-300">
                                                {{ $msg->toolExecutionLogs->count() }} Eksekusi
                                            </span>
                                        </div>

                                        @foreach ($msg->toolExecutionLogs as $toolLog)
                                            <div x-data="{ showDetails: false }" class="rounded-xl border border-gray-200 dark:border-gray-700/80 bg-gray-50/75 dark:bg-gray-900/50 p-3.5 space-y-2">
                                                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                                    <div class="flex items-center gap-2">
                                                        <!-- Polymorphic Agent Pill -->
                                                        @if($toolLog->loggable_type === 'App\Models\SecurityScanner')
                                                            <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
                                                                🛡️ SecurityScanner: {{ $toolLog->loggable?->name ?? 'Scanner Agent' }}
                                                            </span>
                                                        @elseif($toolLog->loggable_type === 'App\Models\MalwareScanner')
                                                            <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                                                                🦠 MalwareScanner: {{ $toolLog->loggable?->name ?? 'Malware Agent' }}
                                                            </span>
                                                        @else
                                                            <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                                                                📜 LogAnalyzer: {{ $toolLog->loggable?->name ?? 'Analyzer Agent' }}
                                                            </span>
                                                        @endif

                                                        <!-- Tool Name -->
                                                        <span class="font-mono text-xs font-semibold text-gray-700 dark:text-gray-300">
                                                            {{ $toolLog->tool_name }}
                                                        </span>
                                                    </div>

                                                    <div class="flex items-center gap-2 text-xs">
                                                        <span class="font-mono text-gray-500 dark:text-gray-400">⏱️ {{ $toolLog->execution_time_ms }} ms</span>
                                                        <span class="px-2 py-0.5 rounded text-[11px] font-bold uppercase {{ $toolLog->status === 'success' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300' : 'bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300' }}">
                                                            {{ $toolLog->status }}
                                                        </span>
                                                        <button @click="showDetails = !showDetails" class="text-indigo-600 dark:text-indigo-400 font-semibold hover:underline text-xs ml-1">
                                                            <span x-text="showDetails ? 'Tutup Payload' : 'Lihat Payload'"></span>
                                                        </button>
                                                    </div>
                                                </div>

                                                <!-- Payload Details Drawer -->
                                                <div x-show="showDetails" x-cloak class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs font-mono">
                                                    <!-- Input Parameters -->
                                                    <div class="p-2.5 rounded-lg bg-gray-900 text-gray-200 border border-gray-800">
                                                        <span class="text-gray-400 font-bold block mb-1">Input Parameters (JSON):</span>
                                                        <pre class="overflow-x-auto text-[11px] text-sky-300">{{ json_encode($toolLog->input_parameters, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
                                                    </div>

                                                    <!-- Output Payload -->
                                                    <div class="p-2.5 rounded-lg bg-gray-900 text-gray-200 border border-gray-800">
                                                        <span class="text-gray-400 font-bold block mb-1">Output Payload (JSON):</span>
                                                        <pre class="overflow-x-auto text-[11px] text-emerald-300">{{ json_encode($toolLog->output_payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
                                                    </div>
                                                </div>
                                            </div>
                                        @endforeach
                                    </div>
                                @endif

                            </div>
                        </div>
                    @endif
                @endforeach
            </div>

            <!-- SEND MESSAGE FORM -->
            <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700/60 p-4 sticky bottom-4 z-10 backdrop-blur-md bg-white/95 dark:bg-gray-800/95">
                <form action="{{ route('chat.message', $chatSession->id) }}" method="POST" class="space-y-3">
                    @csrf
                    <!-- Suggestion Chips -->
                    <div class="flex flex-wrap items-center gap-2 text-xs">
                        <span class="text-gray-500 dark:text-gray-400 font-medium">Contoh Prompt Cepat:</span>
                        <button type="button" onclick="document.getElementById('messageInput').value = 'Scan network 192.168.1.0/24 for exposed vulnerabilities and open ports.'" class="px-2.5 py-1 rounded-lg bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-indigo-50 hover:text-indigo-600 transition">
                            🛡️ Scan Network Ports
                        </button>
                        <button type="button" onclick="document.getElementById('messageInput').value = 'Analyze malware payload binary in /var/quarantine/sample.bin with YARA signatures.'" class="px-2.5 py-1 rounded-lg bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-rose-50 hover:text-rose-600 transition">
                            🦠 Heuristic Malware Scan
                        </button>
                        <button type="button" onclick="document.getElementById('messageInput').value = 'Inspect auth.log for SSH brute force attacks and SQL injection patterns.'" class="px-2.5 py-1 rounded-lg bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-amber-50 hover:text-amber-600 transition">
                            📜 Correlate Log Anomalies
                        </button>
                    </div>

                    <div class="flex items-center gap-3">
                        <input id="messageInput" type="text" name="content" required placeholder="Ketik perintah investigasi untuk agen AI..." class="flex-1 px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 text-sm">
                        <button type="submit" class="inline-flex items-center gap-2 px-5 py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm rounded-xl shadow-md shadow-indigo-600/25 transition">
                            <span>Kirim & Eksekusi Alat</span>
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path>
                            </svg>
                        </button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</x-app-layout>
