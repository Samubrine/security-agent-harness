<?php

namespace App\Agent\Tools;

use App\Agent\Harness\HarnessException;
use App\Agent\Harness\RunArchive;
use Illuminate\Database\Eloquent\Model;

class GetInvestigationTool implements AgentTool
{
    public function __construct(private readonly RunArchive $archive) {}

    public function name(): string
    {
        return 'get_investigation';
    }

    public function description(): string
    {
        return 'Read the full findings of one earlier investigation: every finding with its evidence statements, explanation, related CVEs and evidence gaps.';
    }

    public function parameters(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'run_id' => ['type' => 'string', 'description' => 'The run_id, e.g. run-20261103T101500-ab12.'],
            ],
            'required' => ['run_id'],
        ];
    }

    public function loggable(array $arguments): Model
    {
        return FindingsArchive::source();
    }

    public function execute(array $arguments): array
    {
        try {
            return $this->archive->summary((string) ($arguments['run_id'] ?? ''), detailed: true);
        } catch (HarnessException $e) {
            throw new ToolException($e->getMessage().' Call list_investigations to see valid run ids.', 0, $e);
        }
    }
}
