<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('security_scanners', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('scanner_type')->default('network_vulnerability');
            $table->string('engine')->default('nmap_v7');
            $table->string('target_scope')->nullable();
            $table->string('version')->default('1.2.0');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_scanners');
    }
};
