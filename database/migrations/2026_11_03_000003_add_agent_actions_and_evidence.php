<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('chat_messages', function (Blueprint $table) {
            // Something the operator must answer before the agent can continue: an approval for a
            // risky harness call, or missing context (which machine?). Null when nothing is pending.
            $table->json('pending_action')->nullable()->after('reasoning');
            // Result of checking the answer's CVE ids, CVSS scores and run ids against the evidence.
            $table->json('claim_check')->nullable()->after('pending_action');
        });

        // Every successful tool result is kept as a content-addressed evidence artifact, so an
        // answer's claims can be traced to (and checked against) what a tool actually returned.
        Schema::create('evidence_artifacts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('chat_session_id')->constrained()->cascadeOnDelete();
            $table->foreignId('tool_execution_log_id')->constrained()->cascadeOnDelete();
            $table->string('kind', 64);
            $table->string('source', 512);
            $table->char('sha256', 64)->index();
            $table->json('content');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('evidence_artifacts');
        Schema::table('chat_messages', function (Blueprint $table) {
            $table->dropColumn(['pending_action', 'claim_check']);
        });
    }
};
