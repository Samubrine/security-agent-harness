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
        Schema::create('log_analyzers', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('log_format')->default('apache_combined');
            $table->string('pattern_ruleset')->default('owasp_crs_v4');
            $table->string('severity_threshold')->default('warning');
            $table->string('version')->default('1.4.0');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('log_analyzers');
    }
};
