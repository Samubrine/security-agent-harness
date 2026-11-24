<?php

namespace Tests\Feature;

use App\Livewire\CariMahasiswa;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;
use Tests\TestCase;

class CariMahasiswaTest extends TestCase
{
    use RefreshDatabase;

    public function test_authenticated_user_can_access_mahasiswa_search_page(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get(route('mahasiswa.index'));

        $response->assertStatus(200);
        $response->assertSeeLivewire(CariMahasiswa::class);
        $response->assertSee('Pencarian Mahasiswa Real-Time (Tanpa Tombol)');
    }

    public function test_search_filters_mahasiswa_by_name_in_real_time(): void
    {
        Livewire::test(CariMahasiswa::class)
            ->assertSee('Mikail Ibrahim Hakim')
            ->assertSee('Budi Santoso')
            ->set('cari', 'Mikail')
            ->assertSee('Mikail Ibrahim Hakim')
            ->assertDontSee('Budi Santoso');
    }

    public function test_search_filters_mahasiswa_by_nrp_in_real_time(): void
    {
        Livewire::test(CariMahasiswa::class)
            ->set('cari', '5025241097')
            ->assertSee('Adriel Mahira Dharma')
            ->assertDontSee('Budi Santoso');
    }

    public function test_reset_cari_clears_filter(): void
    {
        Livewire::test(CariMahasiswa::class)
            ->set('cari', 'Adi')
            ->assertSee('Muhammad Adi Anugerah Arrahman')
            ->call('resetCari')
            ->assertSet('cari', '');
    }
}
