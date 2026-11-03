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
        Schema::create('tool_execution_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('chat_message_id')
                ->constrained('chat_messages')
                ->onDelete('cascade');
            $table->string('tool_name');
            $table->enum('status', ['running', 'success', 'failed', 'timeout'])->default('success');
            $table->json('input_parameters')->nullable();
            $table->json('output_payload')->nullable();
            $table->unsignedInteger('execution_time_ms')->default(0);
            // Polymorphic helper for Challenge 1: Polymorphic Logging
            $table->morphs('loggable');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('tool_execution_logs');
    }
};
