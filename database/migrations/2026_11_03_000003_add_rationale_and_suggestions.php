<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('tool_execution_logs', function (Blueprint $table) {
            // The agent's own one-sentence reason for making this call (shown in the UI).
            $table->text('rationale')->nullable()->after('tool_name');
        });

        Schema::table('chat_messages', function (Blueprint $table) {
            // Follow-up actions the agent proposes at the end of an answer (list of strings).
            $table->json('suggestions')->nullable()->after('reasoning');
        });
    }

    public function down(): void
    {
        Schema::table('tool_execution_logs', fn (Blueprint $table) => $table->dropColumn('rationale'));
        Schema::table('chat_messages', fn (Blueprint $table) => $table->dropColumn('suggestions'));
    }
};
