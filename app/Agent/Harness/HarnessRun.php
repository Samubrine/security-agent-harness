<?php

namespace App\Agent\Harness;

/**
 * The result of one harness investigation, as recorded in its run directory.
 */
final class HarnessRun
{
    /**
     * @param  array<string, mixed>  $summary  the CLI's --json summary
     */
    public function __construct(
        public readonly string $runId,
        public readonly string $runDir,
        public readonly array $summary,
        public readonly string $planner,
        public readonly ?string $fallbackReason = null,
    ) {}
}
