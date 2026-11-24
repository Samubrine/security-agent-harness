<?php

namespace App\Livewire;

use App\Models\Mahasiswa;
use Illuminate\Contracts\View\View;
use Livewire\Component;
use Livewire\WithPagination;

class CariMahasiswa extends Component
{
    use WithPagination;

    public string $cari = '';

    public function updatingCari(): void
    {
        $this->resetPage();
    }

    public function resetCari(): void
    {
        $this->cari = '';
        $this->resetPage();
    }

    public function render(): View
    {
        $data = Mahasiswa::where('nama', 'like', '%'.$this->cari.'%')
            ->orWhere('nrp', 'like', '%'.$this->cari.'%')
            ->orderBy('nrp', 'asc')
            ->paginate(5);

        return view('livewire.cari-mahasiswa', ['mahasiswas' => $data]);
    }
}
