<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('mahasiswas', function (Blueprint $table) {
            $table->id();
            $table->string('nrp', 20)->unique();
            $table->string('nama', 100);
            $table->string('departemen', 100)->default('Teknik Informatika');
            $table->string('dosen_pembimbing', 100)->default('Dr. Eng. Dosen Pembimbing, S.T., M.Kom.');
            $table->string('status', 30)->default('Aktif');
            $table->timestamps();
        });

        // Seed initial ITS student data for real-time demonstration
        $now = now();
        DB::table('mahasiswas')->insert([
            ['nrp' => '5025241046', 'nama' => 'Mikail Ibrahim Hakim', 'departemen' => 'Teknik Informatika', 'dosen_pembimbing' => 'Dr. Ir. Dosen AI & Keamanan, M.Sc.', 'status' => 'Bimbingan Final Project', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025241094', 'nama' => 'Fayza Lathifah Humam', 'departemen' => 'Teknik Informatika', 'dosen_pembimbing' => 'Dr. Ir. Dosen AI & Keamanan, M.Sc.', 'status' => 'Bimbingan Final Project', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025241097', 'nama' => 'Adriel Mahira Dharma', 'departemen' => 'Teknik Informatika', 'dosen_pembimbing' => 'Dr. Ir. Dosen AI & Keamanan, M.Sc.', 'status' => 'Bimbingan Final Project', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025241118', 'nama' => 'Muhammad Adi Anugerah Arrahman', 'departemen' => 'Teknik Informatika', 'dosen_pembimbing' => 'Dr. Ir. Dosen AI & Keamanan, M.Sc.', 'status' => 'Bimbingan Final Project', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025241164', 'nama' => 'Alfianz Risqia Ilahi Loven Kary', 'departemen' => 'Teknik Informatika', 'dosen_pembimbing' => 'Dr. Ir. Dosen AI & Keamanan, M.Sc.', 'status' => 'Bimbingan Final Project', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025231001', 'nama' => 'Budi Santoso', 'departemen' => 'Sistem Informasi', 'dosen_pembimbing' => 'Prof. Dr. Pembimbing SI, M.Kom.', 'status' => 'Aktif', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025231015', 'nama' => 'Siti Nurhaliza', 'departemen' => 'Teknik Komputer', 'dosen_pembimbing' => 'Dr. Pembimbing Tekkom, S.T., M.T.', 'status' => 'Aktif', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025231088', 'nama' => 'Ahmad Fauzi', 'departemen' => 'Teknologi Informasi', 'dosen_pembimbing' => 'Dr. Pembimbing TI, M.Sc.', 'status' => 'Aktif', 'created_at' => $now, 'updated_at' => $now],
            ['nrp' => '5025231120', 'nama' => 'Rina Kartika', 'departemen' => 'Sains Data', 'dosen_pembimbing' => 'Dr. Pembimbing Sains Data, Ph.D.', 'status' => 'Aktif', 'created_at' => $now, 'updated_at' => $now],
        ]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('mahasiswas');
    }
};
