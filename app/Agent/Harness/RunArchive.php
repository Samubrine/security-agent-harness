<?php

namespace App\Agent\Harness;

use Illuminate\Support\Str;

/**
 * Reads finished harness run directories (findings.json, gaps.jsonl, run.json) and turns them
 * into compact, model-friendly summaries.
 *
 * Everything read here originated from scanned hosts and log files, i.e. attacker-controllable
 * data. It is passed to the model as tool output, never as instructions.
 */
class RunArchive
{
    public function __construct(private readonly string $runsDir) {}

    public static function fromConfig(): self
    {
        return new self(config('agent.harness.runs_dir'));
    }

    public function exists(string $runId): bool
    {
        return $this->dirFor($runId) !== null;
    }

    /**
     * @return list<array<string, mixed>> newest first
     */
    public function list(int $limit = 10): array
    {
        $dirs = glob($this->runsDir.DIRECTORY_SEPARATOR.'run-*', GLOB_ONLYDIR) ?: [];
        rsort($dirs);
        $out = [];
        foreach (array_slice($dirs, 0, $limit) as $dir) {
            $run = $this->readJson($dir.'/run.json') ?? [];
            $findings = $this->readJson($dir.'/findings.json') ?? [];
            $out[] = [
                'run_id' => basename($dir),
                'skill' => $run['skill'] ?? null,
                'objective' => isset($run['objective']) ? Str::limit((string) $run['objective'], 160) : null,
                'status' => $run['status'] ?? null,
                'created_at' => $run['created_at'] ?? null,
                'findings' => count($findings),
                'top_findings' => array_map(
                    fn ($f) => ($f['severity'] ?? '?').': '.($f['title'] ?? ''),
                    array_slice($this->bySeverity($findings), 0, 3),
                ),
            ];
        }

        return $out;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws HarnessException
     */
    public function summary(string $runId, bool $detailed = false): array
    {
        $dir = $this->dirFor($runId) ?? throw new HarnessException("No investigation with run_id `{$runId}`.");
        $run = $this->readJson($dir.'/run.json') ?? [];
        $findings = $this->bySeverity($this->readJson($dir.'/findings.json') ?? []);
        $gaps = $this->readJsonl($dir.'/gaps.jsonl');
        $claimLimit = $detailed ? 10 : 2;

        return [
            'run_id' => basename($dir),
            'skill' => $run['skill'] ?? null,
            'objective' => $run['objective'] ?? null,
            'status' => $run['status'] ?? null,
            'stop_reason' => $run['stop_reason'] ?? null,
            'model' => $run['model']['model_id'] ?? null,
            'findings' => array_map(fn ($f) => [
                'id' => $f['id'] ?? null,
                'title' => $f['title'] ?? null,
                'severity' => $f['severity'] ?? null,
                // confirmed = observed directly in evidence; possible = inferred (e.g. a version
                // falls inside a CVE's affected range) and needs verification.
                'status' => $f['status'] ?? null,
                'cves' => $f['cve'] ?? [],
                'products' => $f['cpe'] ?? [],
                'evidence' => array_map(
                    fn ($c) => Str::limit((string) ($c['statement'] ?? ''), $detailed ? 400 : 220),
                    array_slice($f['claims'] ?? [], 0, $claimLimit),
                ),
                'more_evidence' => max(0, count($f['claims'] ?? []) - $claimLimit),
                'explanation' => $detailed ? ($f['narrative'] ?? null) : null,
            ], $findings),
            'evidence_gaps' => array_map(fn ($g) => [
                'kind' => $g['kind'] ?? null,
                'impact' => Str::limit((string) ($g['impact'] ?? ''), 300),
            ], array_slice($gaps, 0, $detailed ? 10 : 3)),
        ];
    }

    private function dirFor(string $runId): ?string
    {
        if (! preg_match('/^run-[A-Za-z0-9T-]{4,64}$/', $runId)) {
            return null;
        }
        $dir = $this->runsDir.DIRECTORY_SEPARATOR.$runId;

        return is_dir($dir) ? $dir : null;
    }

    /**
     * @param  list<array<string, mixed>>  $findings
     * @return list<array<string, mixed>>
     */
    private function bySeverity(array $findings): array
    {
        $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($findings, fn ($a, $b) => ($rank[$a['severity'] ?? 'info'] ?? 5) <=> ($rank[$b['severity'] ?? 'info'] ?? 5));

        return $findings;
    }

    private function readJson(string $path): mixed
    {
        return is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function readJsonl(string $path): array
    {
        if (! is_file($path)) {
            return [];
        }
        $rows = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $row = json_decode($line, true);
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        return $rows;
    }
}
