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
            'cross_checks' => $this->crossChecks($dir),
            'approvals' => $approvals = $this->approvals($dir),
            // Requests that were declined only because nobody was there to answer: the operator can
            // approve them and run the investigation again.
            'approval_needed' => array_values(array_filter($approvals, fn ($a) => $a['awaiting_operator'])),
            'evidence_gaps' => array_map(fn ($g) => [
                'kind' => $g['kind'] ?? null,
                'impact' => Str::limit((string) ($g['impact'] ?? ''), 300),
            ], array_slice($gaps, 0, $detailed ? 10 : 3)),
        ];
    }

    /**
     * Where two independent providers described the same thing: did they agree?
     *
     * @return list<array{subject: string, relation: string, sources: list<array{provider: string, version: ?string}>}>
     */
    private function crossChecks(string $dir): array
    {
        $rows = $this->readJsonl($dir.'/correlations.jsonl');
        if ($rows === []) {
            return [];
        }
        $observations = collect($this->readJson($dir.'/observations.json') ?? [])->keyBy('id');

        return array_map(fn ($c) => [
            'subject' => HarnessEvents::subject((string) ($c['key'] ?? '')),
            'relation' => (string) ($c['relation'] ?? ''),
            'sources' => array_values(array_map(fn ($id) => [
                'provider' => HarnessEvents::provider((string) ($observations[$id]['provider'] ?? '?')),
                'version' => $observations[$id]['value']['version'] ?? null,
            ], $c['observation_ids'] ?? [])),
        ], $rows);
    }

    /**
     * Approval requests the harness raised, with the policy's reason and the answer.
     *
     * @return list<array{provider: string, provider_id: string, capability: string, reason: string, approved: bool, answer: string, awaiting_operator: bool}>
     */
    private function approvals(string $dir): array
    {
        $events = $this->readJsonl($dir.'/events.jsonl');
        $reasons = [];
        $requests = [];
        $answers = [];
        foreach ($events as $event) {
            $d = $event['data'] ?? [];
            match ($event['type'] ?? '') {
                'POLICY_DECIDED' => ($d['verdict'] ?? null) === 'ask' ? $reasons[$d['provider'] ?? ''] = $d['reasons'] ?? [] : null,
                'APPROVAL_REQUESTED' => $requests[] = $d,
                'APPROVAL_GIVEN' => $answers[$d['request'] ?? ''] = $d,
                default => null,
            };
        }

        return array_map(function ($r) use ($reasons, $answers) {
            $answer = $answers[$r['request'] ?? ''] ?? [];
            $text = (string) ($answer['answer'] ?? '');

            return [
                'provider' => HarnessEvents::provider((string) ($r['provider'] ?? '')),
                'provider_id' => (string) ($r['provider'] ?? ''),
                'capability' => (string) ($r['capability'] ?? ''),
                'reason' => self::approvalReason($reasons[$r['provider'] ?? ''] ?? []),
                'approved' => (bool) ($answer['approved'] ?? false),
                'answer' => $text,
                'awaiting_operator' => ! ($answer['approved'] ?? false)
                    && (str_contains($text, 'no interactive approver') || str_contains($text, 'answers exhausted')),
            ];
        }, $requests);
    }

    /**
     * @param  list<string>  $codes  policy reason codes
     */
    private static function approvalReason(array $codes): string
    {
        $texts = array_values(array_unique(array_filter(array_map(fn ($code) => match ($code) {
            'run_strict' => 'it is a medium-risk, third-party (MCP) tool, and this installation asks before using those',
            'risk_medium_requires_egress' => 'it is medium risk and would send data off this machine',
            'risk_high' => 'it is a high-risk action',
            'tainted_arguments_t3' => 'its request was built after reading data an attacker could control (the scanned banner)',
            'tainted_novel_resource' => 'it was proposed after reading attacker-controlled data and touches something new',
            default => null,
        }, $codes))));

        return $texts !== [] ? implode('; and ', $texts) : 'the policy engine routed it to a human';
    }

    /**
     * Every recorded run's run.json plus its directory name, newest first. This is the shape the
     * investigation workspace (resources/js/workspace.js) expects.
     *
     * @return list<array<string, mixed>>
     */
    public function records(): array
    {
        $runs = [];
        foreach (glob($this->runsDir.DIRECTORY_SEPARATOR.'run-*', GLOB_ONLYDIR) ?: [] as $dir) {
            if (is_link($dir)) {
                continue;
            }
            $run = $this->readJson($dir.'/run.json');
            if (is_array($run)) {
                $runs[] = $run + ['directory' => basename($dir)];
            }
        }
        usort($runs, fn ($a, $b) => strcmp((string) ($b['created_at'] ?? ''), (string) ($a['created_at'] ?? '')));

        return $runs;
    }

    /**
     * Everything the workspace shows for one run.
     *
     * @return array<string, mixed>
     *
     * @throws HarnessException
     */
    public function full(string $runId): array
    {
        $dir = $this->dirFor($runId);
        if ($dir === null || ! is_file($dir.'/run.json')) {
            throw new HarnessException("No investigation with run_id `{$runId}`.");
        }

        return [
            'run' => $this->readJson($dir.'/run.json') ?? [],
            'findings' => $this->readJson($dir.'/findings.json') ?? [],
            'observations' => $this->readJson($dir.'/observations.json') ?? [],
            'events' => $this->readJsonl($dir.'/events.jsonl'),
            'gaps' => $this->readJsonl($dir.'/gaps.jsonl'),
            'report' => is_file($dir.'/report.md') ? (string) file_get_contents($dir.'/report.md') : 'Report not available yet.',
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
