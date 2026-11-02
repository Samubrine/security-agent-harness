<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * A fourth polymorphic "loggable" type: where the agent looks things up rather than what it
     * scans with — the harness's own findings archive and public vulnerability databases.
     */
    public function up(): void
    {
        Schema::create('knowledge_sources', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->enum('source_type', ['internal_findings', 'public_vulnerability_db']);
            $table->string('provider');
            $table->string('endpoint')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('knowledge_sources');
    }
};
