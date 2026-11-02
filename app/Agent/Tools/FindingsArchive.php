<?php

namespace App\Agent\Tools;

use App\Models\KnowledgeSource;

final class FindingsArchive
{
    public static function source(): KnowledgeSource
    {
        return KnowledgeSource::firstOrCreate(
            ['name' => 'AEGIS Findings Archive'],
            ['source_type' => 'internal_findings', 'provider' => 'security-agent-harness', 'endpoint' => 'storage/app/harness-runs'],
        );
    }
}
