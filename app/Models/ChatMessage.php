<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ChatMessage extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'chat_session_id',
        'role',
        'content',
        'reasoning',
        'token_count',
        'sequence_number',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'token_count' => 'integer',
        'sequence_number' => 'integer',
    ];

    /**
     * Get the chat session that this message belongs to.
     *
     * @return BelongsTo<ChatSession, ChatMessage>
     */
    public function chatSession(): BelongsTo
    {
        return $this->belongsTo(ChatSession::class);
    }

    /**
     * Get all tool execution logs associated with this chat message.
     *
     * @return HasMany<ToolExecutionLog>
     */
    public function toolExecutionLogs(): HasMany
    {
        return $this->hasMany(ToolExecutionLog::class);
    }
}
