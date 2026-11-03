<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;

class LogAnalyzer extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'log_format',
        'pattern_ruleset',
        'severity_threshold',
        'version',
    ];

    /**
     * Get all polymorphic tool execution logs for this log analyzer.
     *
     * @return MorphMany<ToolExecutionLog>
     */
    public function toolExecutionLogs(): MorphMany
    {
        return $this->morphMany(ToolExecutionLog::class, 'loggable');
    }
}
