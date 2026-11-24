<x-app-layout>
    <x-slot name="title">Demo Soal 1: Pencarian Mahasiswa Real-Time</x-slot>
    <x-slot name="section">Livewire Soal 1</x-slot>
    <x-slot name="breadcrumb">Pencarian Mahasiswa</x-slot>

    <div class="page-heading">
        <div>
            <p class="eyebrow">Pertemuan 12 · Skenario Studi Kasus 1</p>
            <h1>Pencarian Mahasiswa Real-Time (Tanpa Tombol)</h1>
            <p class="subtitle" style="font-size:14px;color:var(--text-muted)">
                Implementasi studi kasus Livewire two-way data binding instan menggunakan <code>wire:model.live</code>
            </p>
        </div>
        <div class="actions">
            <a class="button" href="{{ route('chat.show', 1) }}">Kembali ke Agent Workspace</a>
        </div>
    </div>

    {{-- Render Livewire Component --}}
    <livewire:cari-mahasiswa />
</x-app-layout>
