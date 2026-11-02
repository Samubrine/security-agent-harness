<x-app-layout>
    <x-slot name="header">
        <div class="flex items-center justify-between">
            <div>
                <h2 class="font-bold text-xl text-gray-900 dark:text-white leading-tight flex items-center gap-2">
                    <span class="p-1.5 bg-purple-600 text-white rounded-lg">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"></path>
                        </svg>
                    </span>
                    Slide Pitch Presentasi — Kelompok 6 (Maks 5 Halaman)
                </h2>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                    Durasi: 5 Menit • Tugas Pemodelan Relasi Agentic AI Platform (Pertemuan 9-10)
                </p>
            </div>
            <div class="flex items-center gap-2">
                <a href="{{ route('chat.index') }}" class="px-3 py-1.5 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs font-semibold rounded-lg hover:bg-gray-200 transition">
                    Kembali ke Obrolan
                </a>
            </div>
        </div>
    </x-slot>

    <div class="py-6" x-data="{ currentSlide: 1, totalSlides: 5, notes: false }"
         @keydown.right.window="if (currentSlide < totalSlides) currentSlide++"
         @keydown.left.window="if (currentSlide > 1) currentSlide--">

        <div class="max-w-6xl mx-auto sm:px-6 lg:px-8 space-y-4">

            <!-- Presentation Controls Bar -->
            <div class="bg-white dark:bg-gray-800 rounded-xl p-3 shadow-sm border border-gray-100 dark:border-gray-700 flex items-center justify-between">
                <div class="flex items-center gap-2">
                    <span class="text-xs font-bold text-gray-500 uppercase tracking-wider">Halaman Slide:</span>
                    <div class="flex gap-1.5">
                        <template x-for="i in totalSlides" :key="i">
                            <button @click="currentSlide = i"
                                    class="w-8 h-8 rounded-lg text-xs font-bold transition-all flex items-center justify-center"
                                    :class="currentSlide === i ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200'">
                                <span x-text="i"></span>
                            </button>
                        </template>
                    </div>
                </div>

                <div class="flex items-center gap-2">
                    <button @click="notes = !notes" class="px-3 py-1.5 rounded-lg text-xs font-semibold border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                        <span x-text="notes ? 'Sembunyikan Catatan Presenter' : 'Catatan Presenter (Speaker Notes)'"></span>
                    </button>
                    <button @click="if (currentSlide > 1) currentSlide--" :disabled="currentSlide === 1" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 disabled:opacity-40 hover:bg-gray-200 transition">
                        ← Sebelumnya
                    </button>
                    <button @click="if (currentSlide < totalSlides) currentSlide++" :disabled="currentSlide === totalSlides" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 text-white disabled:opacity-40 hover:bg-indigo-500 transition shadow-sm">
                        Selanjutnya →
                    </button>
                </div>
            </div>

            <!-- SLIDE CANVAS -->
            <div class="bg-gradient-to-br from-gray-900 via-slate-900 to-indigo-950 text-white rounded-3xl p-8 sm:p-12 shadow-2xl border border-indigo-900/60 min-h-[580px] flex flex-col justify-between relative overflow-hidden">
                <!-- Ambient Glow Effects -->
                <div class="absolute -top-24 -right-24 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none"></div>
                <div class="absolute -bottom-24 -left-24 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>

                <!-- SLIDE 1: Cover & Team Identity -->
                <div x-show="currentSlide === 1" class="space-y-6 my-auto">
                    <div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        Pertemuan 9 • PBKK • Kelompok 6
                    </div>
                    <h1 class="text-4xl sm:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-indigo-100 to-indigo-300 leading-tight">
                        Pemodelan Basis Data Relasional Platform Agentic AI
                    </h1>
                    <p class="text-lg text-indigo-200/90 max-w-3xl leading-relaxed">
                        Arsitektur relasi komprehensif, pencatatan sesi obrolan, log aktivitas alat bertingkat, serta penyelesaian Tantangan A+ (Polymorphic Logging & Optimasi Bebas N+1 Query).
                    </p>

                    <div class="pt-6 border-t border-indigo-900/50">
                        <span class="text-xs font-semibold uppercase tracking-wider text-indigo-400 block mb-3">Anggota Kelompok 6:</span>
                        <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                            <div class="p-3 rounded-xl bg-white/5 border border-white/10">
                                <span class="text-xs text-indigo-400 font-mono block">5025241046</span>
                                <strong class="text-sm text-white">Mikail Ibrahim Hakim</strong>
                            </div>
                            <div class="p-3 rounded-xl bg-white/5 border border-white/10">
                                <span class="text-xs text-indigo-400 font-mono block">5025241094</span>
                                <strong class="text-sm text-white">Fayza Lathifah Humam</strong>
                            </div>
                            <div class="p-3 rounded-xl bg-white/5 border border-white/10">
                                <span class="text-xs text-indigo-400 font-mono block">5025241097</span>
                                <strong class="text-sm text-white">Adriel Mahira Dharma</strong>
                            </div>
                            <div class="p-3 rounded-xl bg-white/5 border border-white/10">
                                <span class="text-xs text-indigo-400 font-mono block">5025241118</span>
                                <strong class="text-sm text-white">Muhammad Adi Anugerah Arrahman</strong>
                            </div>
                            <div class="p-3 rounded-xl bg-white/5 border border-white/10">
                                <span class="text-xs text-indigo-400 font-mono block">5025241164</span>
                                <strong class="text-sm text-white">Alfianz Risqia Ilahi Loven Kary</strong>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- SLIDE 2: ERD & Relational Foundation -->
                <div x-show="currentSlide === 2" class="space-y-6 my-auto">
                    <div class="flex items-center justify-between">
                        <span class="px-3 py-1 rounded-full text-xs font-bold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/30">
                            Slide 2 • Fondasi Skema Relasional
                        </span>
                        <span class="text-xs font-mono text-gray-400">onDelete('cascade') Integrity</span>
                    </div>

                    <h2 class="text-3xl font-extrabold text-white">Entity-Relationship Diagram (ERD) & 4 Model Utama</h2>

                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 pt-2">
                        <div class="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2">
                            <span class="text-xs font-bold text-blue-400 uppercase">1. User (Breeze)</span>
                            <p class="text-xs text-gray-300">Entitas operator manusia.</p>
                            <div class="p-2 bg-black/40 rounded font-mono text-[11px] text-emerald-400">
                                hasMany(ChatSession)
                            </div>
                        </div>
                        <div class="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2">
                            <span class="text-xs font-bold text-indigo-400 uppercase">2. ChatSession</span>
                            <p class="text-xs text-gray-300">Wadah konteks investigasi AI.</p>
                            <div class="p-2 bg-black/40 rounded font-mono text-[11px] text-indigo-300">
                                belongsTo(User)<br>hasMany(ChatMessage)
                            </div>
                        </div>
                        <div class="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2">
                            <span class="text-xs font-bold text-purple-400 uppercase">3. ChatMessage</span>
                            <p class="text-xs text-gray-300">Butir prompt & respons AI.</p>
                            <div class="p-2 bg-black/40 rounded font-mono text-[11px] text-purple-300">
                                belongsTo(ChatSession)<br>hasMany(ToolExecutionLog)
                            </div>
                        </div>
                        <div class="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2">
                            <span class="text-xs font-bold text-pink-400 uppercase">4. ToolExecutionLog</span>
                            <p class="text-xs text-gray-300">Log pemanggilan tool agen.</p>
                            <div class="p-2 bg-black/40 rounded font-mono text-[11px] text-pink-300">
                                belongsTo(ChatMessage)<br>morphTo('loggable')
                            </div>
                        </div>
                    </div>

                    <div class="p-4 rounded-xl bg-black/40 border border-white/10 font-mono text-xs text-gray-300 space-y-1">
                        <div class="text-indigo-400 font-bold mb-1">Integritas Relasi Basis Data:</div>
                        <div>• <span class="text-emerald-400">users</span> (1) ──&lt; <span class="text-indigo-300">chat_sessions</span> (N) [FK: user_id ON DELETE CASCADE]</div>
                        <div>• <span class="text-indigo-300">chat_sessions</span> (1) ──&lt; <span class="text-purple-300">chat_messages</span> (N) [FK: chat_session_id ON DELETE CASCADE]</div>
                        <div>• <span class="text-purple-300">chat_messages</span> (1) ──&lt; <span class="text-pink-300">tool_execution_logs</span> (N) [FK: chat_message_id ON DELETE CASCADE]</div>
                    </div>
                </div>

                <!-- SLIDE 3: Challenge 1 - Polymorphic Logging -->
                <div x-show="currentSlide === 3" class="space-y-6 my-auto">
                    <div class="flex items-center justify-between">
                        <span class="px-3 py-1 rounded-full text-xs font-bold uppercase bg-pink-500/20 text-pink-300 border border-pink-500/30">
                            Slide 3 • Tantangan 1 (Challenge A+)
                        </span>
                        <span class="text-xs font-mono text-emerald-400 font-bold">morphs('loggable')</span>
                    </div>

                    <h2 class="text-3xl font-extrabold text-white">Polymorphic Logging untuk Beragam Agen Khusus</h2>

                    <p class="text-sm text-gray-300">
                        Satu tabel <code class="bg-black/50 px-2 py-0.5 rounded text-pink-300 font-mono">tool_execution_logs</code> dapat direferensikan secara dinamis oleh tipe model Agent yang berbeda tanpa membuat tabel log terpisah untuk tiap agen.
                    </p>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
                        <div class="p-4 rounded-xl bg-gradient-to-b from-blue-900/40 to-blue-950/40 border border-blue-500/30 space-y-2">
                            <strong class="text-blue-300 text-sm block">🛡️ SecurityScanner</strong>
                            <p class="text-xs text-gray-300">Pemindaian port, CVE, dan service banner (Nmap/Masscan).</p>
                            <div class="text-[11px] font-mono text-blue-400 pt-2 border-t border-blue-800/40">
                                morphMany(ToolExecutionLog, 'loggable')
                            </div>
                        </div>

                        <div class="p-4 rounded-xl bg-gradient-to-b from-rose-900/40 to-rose-950/40 border border-rose-500/30 space-y-2">
                            <strong class="text-rose-300 text-sm block">🦠 MalwareScanner</strong>
                            <p class="text-xs text-gray-300">Deteksi heuristic, YARA bytecode & static disassembly (ClamAV).</p>
                            <div class="text-[11px] font-mono text-rose-400 pt-2 border-t border-rose-800/40">
                                morphMany(ToolExecutionLog, 'loggable')
                            </div>
                        </div>

                        <div class="p-4 rounded-xl bg-gradient-to-b from-amber-900/40 to-amber-950/40 border border-amber-500/30 space-y-2">
                            <strong class="text-amber-300 text-sm block">📜 LogAnalyzer</strong>
                            <p class="text-xs text-gray-300">Audit log akses web, korelasi OWASP SQLi, dan brute force auth.</p>
                            <div class="text-[11px] font-mono text-amber-400 pt-2 border-t border-amber-800/40">
                                morphMany(ToolExecutionLog, 'loggable')
                            </div>
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-black/50 border border-white/10 font-mono text-xs text-gray-300">
                        <span class="text-purple-400">Migrasi:</span> $table-&gt;morphs('loggable'); <span class="text-gray-500">// Menghasilkan kolom loggable_type (VARCHAR) & loggable_id (BIGINT) terindeks</span>
                    </div>
                </div>

                <!-- SLIDE 4: Challenge 2 - Eager Loading Optimization -->
                <div x-show="currentSlide === 4" class="space-y-6 my-auto">
                    <div class="flex items-center justify-between">
                        <span class="px-3 py-1 rounded-full text-xs font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            Slide 4 • Tantangan 2 (Challenge A+)
                        </span>
                        <span class="text-xs font-mono text-emerald-400 font-bold">Zero N+1 Query Guarantee</span>
                    </div>

                    <h2 class="text-3xl font-extrabold text-white">Optimasi Kueri Riwayat Obrolan: Solusi N+1 Query</h2>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="p-4 rounded-xl bg-rose-950/30 border border-rose-600/30 space-y-2">
                            <div class="flex items-center gap-2">
                                <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                                <strong class="text-rose-300 text-sm">Masalah: Lazy Loading (N+1 Query)</strong>
                            </div>
                            <p class="text-xs text-gray-300">
                                Saat memuat sesi, lalu looping pesan, lalu looping log alat, lalu membaca agen:
                            </p>
                            <div class="p-2.5 bg-black/50 rounded font-mono text-[11px] text-rose-300">
                                1 + (N pesan) + (M log alat) + (K agen)<br>
                                = <span class="text-rose-400 font-bold">25 - 50+ Kueri SQL</span> dieksekusi berulang!
                            </div>
                        </div>

                        <div class="p-4 rounded-xl bg-emerald-950/30 border border-emerald-600/30 space-y-2">
                            <div class="flex items-center gap-2">
                                <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                <strong class="text-emerald-300 text-sm">Solusi: Nested Eager Loading</strong>
                            </div>
                            <p class="text-xs text-gray-300">
                                Menggunakan eager loading bertingkat pada controller obrolan:
                            </p>
                            <div class="p-2.5 bg-black/50 rounded font-mono text-[11px] text-emerald-300">
                                ChatSession::with([<br>
                                &nbsp;&nbsp;'user',<br>
                                &nbsp;&nbsp;'chatMessages.toolExecutionLogs.loggable'<br>
                                ])-&gt;findOrFail($id);<br>
                                = <span class="text-emerald-400 font-bold">Hanya ~5-6 Kueri Konstan!</span>
                            </div>
                        </div>
                    </div>

                    <div class="p-4 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between text-xs">
                        <div class="flex items-center gap-3">
                            <span class="p-2 bg-indigo-600 rounded-lg text-white font-bold">Debugbar</span>
                            <span class="text-gray-300">Terbukti bebas N+1 via <strong>Laravel Debugbar</strong> & pengujian unit <strong>PHPUnit Test: 31 passed</strong>.</span>
                        </div>
                        <span class="font-mono text-emerald-400 font-bold">Latency: 2-4 ms</span>
                    </div>
                </div>

                <!-- SLIDE 5: Live Demo & Summary -->
                <div x-show="currentSlide === 5" class="space-y-6 my-auto">
                    <div class="flex items-center justify-between">
                        <span class="px-3 py-1 rounded-full text-xs font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30">
                            Slide 5 • Kesimpulan & Bukti Implementasi
                        </span>
                        <span class="text-xs font-mono text-gray-400">Rubrik Evaluasi 100% Tercapai</span>
                    </div>

                    <h2 class="text-3xl font-extrabold text-white">Ringkasan Evaluasi & Kesiapan Produksi</h2>

                    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3.5 pt-1">
                        <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                            <span class="text-[11px] text-indigo-400 font-bold block uppercase">Skema & Migrasi (35%)</span>
                            <p class="text-xs text-gray-300 mt-1">FK onDelete('cascade') aktif penuh, UUID token terindeks, aman dari orphan records.</p>
                        </div>
                        <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                            <span class="text-[11px] text-indigo-400 font-bold block uppercase">Model & ORM (25%)</span>
                            <p class="text-xs text-gray-300 mt-1">Konvensi plural/singular PSR-12, hasMany & belongsTo terstruktur rapi.</p>
                        </div>
                        <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                            <span class="text-[11px] text-indigo-400 font-bold block uppercase">Optimasi Eager Loading (20%)</span>
                            <p class="text-xs text-gray-300 mt-1">Kueri with() bertingkat terverifikasi bebas N+1 di Laravel Debugbar & Benchmark UI.</p>
                        </div>
                        <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                            <span class="text-[11px] text-emerald-400 font-bold block uppercase">Tantangan A+ (10%)</span>
                            <p class="text-xs text-gray-300 mt-1">Polymorphic Logging aktif untuk SecurityScanner, MalwareScanner, LogAnalyzer.</p>
                        </div>
                        <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                            <span class="text-[11px] text-indigo-400 font-bold block uppercase">Dokumentasi ERD (10%)</span>
                            <p class="text-xs text-gray-300 mt-1">Mermaid ERD visual lengkap dengan kamus data komprehensif di README.md.</p>
                        </div>
                        <div class="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/30">
                            <span class="text-[11px] text-emerald-300 font-bold block uppercase">PHPUnit Test Suite</span>
                            <p class="text-xs text-gray-200 mt-1">31 Tests Passed, 105 Assertions. Integritas cascade & relasi 100% lolos pengujian.</p>
                        </div>
                    </div>

                    <div class="pt-4 flex items-center justify-between border-t border-indigo-900/50">
                        <span class="text-xs text-indigo-300 font-medium">Terima Kasih — Kelompok 6 (PBKK 2026)</span>
                        <a href="{{ route('chat.index') }}" class="px-4 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-xl text-xs font-bold shadow-md hover:from-indigo-500 hover:to-purple-500 transition">
                            Buka Demo Interaktif Obrolan AI →
                        </a>
                    </div>
                </div>

                <!-- Slide Footer -->
                <div class="pt-6 border-t border-white/10 flex items-center justify-between text-xs text-gray-400">
                    <span>Platform Agentic AI • Kelompok 6</span>
                    <span class="font-mono">Halaman <span x-text="currentSlide" class="text-indigo-400 font-bold"></span> dari <span x-text="totalSlides"></span></span>
                </div>
            </div>

            <!-- Presenter Speaker Notes Drawer -->
            <div x-show="notes" x-cloak class="bg-gray-900 text-gray-300 rounded-2xl p-5 border border-gray-800 text-xs space-y-3 font-mono">
                <div class="text-indigo-400 font-bold uppercase tracking-wider">🎙️ Panduan Presenter (Estimasi 5 Menit Total):</div>
                <div x-show="currentSlide === 1">
                    <strong>Menit 0:00 - 0:45:</strong> Buka dengan perkenalan Kelompok 6 dan visi proyek (membangun pondasi database relasional yang robust untuk mencatat percakapan AI dan pemanggilan tool otomatis).
                </div>
                <div x-show="currentSlide === 2">
                    <strong>Menit 0:45 - 2:00:</strong> Jelaskan 4 model utama (User -&gt; ChatSession -&gt; ChatMessage -&gt; ToolExecutionLog) dan pentingnya cascade on delete agar penghapusan sesi obrolan secara otomatis membersihkan semua pesan dan log pemanggilan alat di bawahnya.
                </div>
                <div x-show="currentSlide === 3">
                    <strong>Menit 2:00 - 3:00:</strong> Soroti Tantangan 1 (Polymorphic Logging). Jelaskan helper morphs('loggable') yang memungkinkan SecurityScanner, MalwareScanner, dan LogAnalyzer saling berbagi satu tabel log tanpa skema database yang kaku.
                </div>
                <div x-show="currentSlide === 4">
                    <strong>Menit 3:00 - 4:15:</strong> Soroti Tantangan 2 (Optimasi Eager Loading). Tunjukkan kontras antara Lazy Loading yang memicu puluhan query N+1 vs Nested Eager Loading dengan with() yang menekan query menjadi ~5-6 kueri saja. Buktikan lewat fitur switch mode di aplikasi dan Laravel Debugbar.
                </div>
                <div x-show="currentSlide === 5">
                    <strong>Menit 4:15 - 5:00:</strong> Tutup presentasi dengan rangkuman rubrik evaluasi dan undang dosen/audiens untuk sesi tanya jawab atau melihat live demo interaktif.
                </div>
            </div>

        </div>
    </div>
</x-app-layout>
