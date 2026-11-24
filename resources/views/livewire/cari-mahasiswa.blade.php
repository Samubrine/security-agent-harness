<div class="mahasiswa-search-container" aria-label="Livewire Real-Time Search Demo">
    {{-- Context Banner (Pertemuan 12 - Slide 28) --}}
    <div class="scenario-card">
        <div class="scenario-badge">
            <span class="pulse-dot" aria-hidden="true"></span>
            <span>STUDI KASUS 1 · PERTEMUAN 12 (SLIDE 28)</span>
        </div>
        <h2 class="scenario-title">Pencarian Mahasiswa Real-Time Tanpa Tombol 'Cari'</h2>
        <p class="scenario-desc">
            Skenario: Mahasiswa mengeluh malas memencet tombol 'Cari'. Sistem menggunakan <code>wire:model.live="cari"</code> 
            untuk menyinkronkan setiap ketukan keyboard ke server secara instan, dipadukan dengan kueri Eloquent 
            <code>Mahasiswa::where(...)->orWhere(...)</code> di dalam method <code>render()</code> tanpa reload halaman.
        </p>
    </div>

    {{-- Search Input Box --}}
    <div class="search-box-card">
        <div class="search-input-wrap">
            <span class="search-icon" aria-hidden="true">
                <svg class="icon" style="width:16px;height:16px;"><use href="#i-chevron"/></svg>
            </span>
            <input 
                type="text" 
                wire:model.live.debounce.150ms="cari" 
                class="search-input" 
                placeholder="Ketik nama atau NRP (misal: 'Mikail', 'Adriel', atau '5025')..."
                autofocus
            >
            @if ($cari)
                <button type="button" wire:click="resetCari" class="search-clear-btn" title="Reset pencarian">✕</button>
            @endif
        </div>

        <div class="search-status-bar">
            <div class="search-feedback">
                <span wire:loading.remove wire:target="cari">
                    @if ($cari)
                        Menyaring database berdasarkan kata kunci: <strong class="highlight-query">"{{ $cari }}"</strong>
                        · Ditemukan: <strong>{{ $mahasiswas->total() }}</strong> mahasiswa
                    @else
                        Menampilkan seluruh data bimbingan mahasiswa ITS (Total: <strong>{{ $mahasiswas->total() }}</strong> mahasiswa)
                    @endif
                </span>
                <span wire:loading wire:target="cari" class="search-loading-state">
                    <span class="inline-spinner" aria-hidden="true"></span>
                    Menyaring database secara instan di server...
                </span>
            </div>

            <span class="tech-badge">Livewire wire:model.live</span>
        </div>
    </div>

    {{-- Students Table --}}
    <div class="table-responsive-card">
        <table class="mahasiswa-table">
            <thead>
                <tr>
                    <th>NRP</th>
                    <th>Nama Mahasiswa</th>
                    <th>Departemen</th>
                    <th>Dosen Pembimbing</th>
                    <th>Status Bimbingan</th>
                </tr>
            </thead>
            <tbody>
                @forelse ($mahasiswas as $mhs)
                    <tr wire:key="mhs-{{ $mhs->id }}" class="table-row">
                        <td class="col-nrp">
                            <span class="mono-nrp">{{ $mhs->nrp }}</span>
                        </td>
                        <td class="col-nama">
                            <strong>{{ $mhs->nama }}</strong>
                        </td>
                        <td class="col-dept">{{ $mhs->departemen }}</td>
                        <td class="col-dosen">{{ $mhs->dosen_pembimbing }}</td>
                        <td class="col-status">
                            <span class="status-pill {{ str_contains($mhs->status, 'Final Project') ? 'is-fp' : 'is-active' }}">
                                {{ $mhs->status }}
                            </span>
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="5" class="table-empty">
                            <div class="empty-state-wrap">
                                <span class="empty-icon-sub">🔍</span>
                                <strong>Tidak Ada Mahasiswa yang Cocok</strong>
                                <p>Tidak ditemukan data dengan nama atau NRP <em>"{{ $cari }}"</em>.</p>
                                <button type="button" wire:click="resetCari" class="button secondary small">Reset Pencarian</button>
                            </div>
                        </td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>

    {{-- Pagination Bar --}}
    @if ($mahasiswas->hasPages())
        <div class="pagination-footer">
            {{ $mahasiswas->links() }}
        </div>
    @endif
</div>
