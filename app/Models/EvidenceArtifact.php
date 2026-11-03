<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A tool result stored as evidence: what came back, from where, and its SHA-256 over the
 * canonical JSON, so the same content always has the same id.
 */
class EvidenceArtifact extends Model
{
    protected $fillable = ['chat_session_id', 'tool_execution_log_id', 'kind', 'source', 'sha256', 'content'];

    protected $casts = ['content' => 'array'];

    public function toolExecutionLog(): BelongsTo
    {
        return $this->belongsTo(ToolExecutionLog::class);
    }

    public function chatSession(): BelongsTo
    {
        return $this->belongsTo(ChatSession::class);
    }

    /**
     * JSON with object keys sorted at every level: the hashing input.
     */
    public static function canonicalJson(mixed $value): string
    {
        $sort = function (mixed $v) use (&$sort): mixed {
            if (! is_array($v)) {
                return $v;
            }
            if (! array_is_list($v)) {
                ksort($v);
            }

            return array_map($sort, $v);
        };

        return json_encode($sort($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: 'null';
    }
}
