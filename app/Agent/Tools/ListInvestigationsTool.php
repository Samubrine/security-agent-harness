<?php

namespace App\Agent\Tools;

use App\Agent\Harness\RunArchive;
use Illuminate\Database\Eloquent\Model;

class ListInvestigationsTool implements AgentTool
{
    public function __construct(private readonly RunArchive $archive) {}

    public function name(): string
    {
        return 'list_investigations';
    }

    public function description(): string
    {
        return 'List the most recent investigations already run by the harness (newest first), with their skill, status and top findings. '
            .'Use this first when the user asks about earlier results, so you do not repeat work.';
    }

    public function parameters(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 20, 'description' => 'How many runs to list (default 8).'],
            ],
        ];
    }

    public function loggable(array $arguments): Model
    {
        return FindingsArchive::source();
    }

    public function execute(array $arguments): array
    {
        $limit = max(1, min(20, (int) ($arguments['limit'] ?? 8)));
        $runs = $this->archive->list($limit);

        return ['count' => count($runs), 'investigations' => $runs];
    }
}
