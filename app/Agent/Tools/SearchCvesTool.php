<?php

namespace App\Agent\Tools;

use Illuminate\Database\Eloquent\Model;

class SearchCvesTool implements AgentTool
{
    public function __construct(private readonly NvdClient $nvd) {}

    public function name(): string
    {
        return 'search_cves';
    }

    public function description(): string
    {
        return 'Search the public NIST National Vulnerability Database by keyword, e.g. a product and version such as "nginx 1.18.0" or "OpenSSH 8.2". '
            .'Returns the highest-scoring matching CVEs. Keyword search is broad: treat results as candidates, not proof that a host is vulnerable.';
    }

    public function parameters(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'keyword' => ['type' => 'string', 'description' => 'Product and optionally version.'],
                'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 8, 'description' => 'Default 5.'],
            ],
            'required' => ['keyword'],
        ];
    }

    public function loggable(array $arguments): Model
    {
        return $this->nvd->source();
    }

    public function execute(array $arguments): array
    {
        $keyword = trim((string) ($arguments['keyword'] ?? ''));
        if (mb_strlen($keyword) < 3 || mb_strlen($keyword) > 100) {
            throw new ToolException('keyword must be 3-100 characters.');
        }
        $limit = max(1, min(8, (int) ($arguments['limit'] ?? 5)));
        $results = $this->nvd->search($keyword, $limit);

        return ['keyword' => $keyword, 'count' => count($results), 'results' => $results];
    }
}
