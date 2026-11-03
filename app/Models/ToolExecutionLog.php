<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;

class ToolExecutionLog extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'chat_message_id',
        'tool_name',
        'status',
        'input_parameters',
        'output_payload',
        'execution_time_ms',
        'loggable_id',
        'loggable_type',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'input_parameters' => 'array',
        'output_payload' => 'array',
        'execution_time_ms' => 'integer',
    ];

    /**
     * Get the chat message that triggered this tool execution.
     *
     * @return BelongsTo<ChatMessage, ToolExecutionLog>
     */
    public function chatMessage(): BelongsTo
    {
        return $this->belongsTo(ChatMessage::class);
    }

    /**
     * Get the owning loggable agent model (Polymorphic Relationship).
     *
     * Enables flexible logging across various agent types:
     * SecurityScanner, MalwareScanner, LogAnalyzer, etc.
     *
     * @return MorphTo<Model, ToolExecutionLog>
     */
    public function loggable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * The evidence artifact(s) this call produced.
     *
     * @return HasMany<EvidenceArtifact>
     */
    public function evidenceArtifacts(): HasMany
    {
        return $this->hasMany(EvidenceArtifact::class);
    }
}
