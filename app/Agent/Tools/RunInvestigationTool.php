<?php

namespace App\Agent\Tools;

use App\Agent\Harness\HarnessException;
use App\Agent\Harness\HarnessRunner;
use App\Agent\Harness\RunArchive;
use App\Agent\Harness\Scope;
use App\Models\LogAnalyzer;
use App\Models\SecurityScanner;
use Illuminate\Database\Eloquent\Model;

class RunInvestigationTool implements AgentTool
{
    public function __construct(
        private readonly HarnessRunner $runner,
        private readonly RunArchive $archive,
    ) {}

    public function name(): string
    {
        return 'run_investigation';
    }

    public function description(): string
    {
        return 'Start a NEW security investigation with the AEGIS harness against an authorised lab target and return its evidence-backed findings. '
            .'Skills: "port_scan" enumerates open services and versions on a network host and matches them to known CVEs (needs a network target); '
            .'"log_analysis" reads authentication and web server logs for brute force, suspicious logins and reconnaissance (needs a log target); '
            .'"entry_point" combines scan and log evidence into a hypothesis of how an attacker got in (no target, uses the whole scope). '
            .'Takes a few seconds to a minute. Do not re-run an investigation that already answers the question; use get_investigation instead.';
    }

    public function parameters(): array
    {
        try {
            $scope = $this->runner->scope();
        } catch (HarnessException) {
            // No signed scope yet: still describe the tool; execute() will explain what is missing.
            $scope = new Scope('missing', []);
        }

        return [
            'type' => 'object',
            'properties' => [
                'skill' => ['type' => 'string', 'enum' => HarnessRunner::SKILLS],
                'target' => array_filter([
                    'type' => 'string',
                    'enum' => array_values(array_merge($scope->networkTargets(), $scope->logTargets())) ?: null,
                    'description' => 'Scope alias. Network hosts for port_scan: '.implode(', ', $scope->networkTargets())
                        .'. Log sources for log_analysis: '.implode(', ', $scope->logTargets()).'. Omit for entry_point.',
                ]),
                'objective' => ['type' => 'string', 'description' => 'One sentence: what this investigation should find out.'],
            ],
            'required' => ['skill', 'objective'],
        ];
    }

    public function loggable(array $arguments): Model
    {
        if (($arguments['skill'] ?? null) === 'log_analysis') {
            return LogAnalyzer::firstOrCreate(
                ['name' => 'AEGIS Harness · Log Analysis'],
                ['log_format' => 'syslog_auth + nginx_access', 'pattern_ruleset' => 'harness/rules', 'severity_threshold' => 'medium', 'version' => 'harness'],
            );
        }

        return SecurityScanner::firstOrCreate(
            ['name' => 'AEGIS Harness · Service & CVE Scan'],
            ['scanner_type' => 'network_port', 'engine' => 'harness (nmap / recorded fixtures)', 'target_scope' => 'signed lab scope', 'version' => 'harness'],
        );
    }

    public function execute(array $arguments): array
    {
        $skill = (string) ($arguments['skill'] ?? '');
        $target = isset($arguments['target']) && $arguments['target'] !== '' ? (string) $arguments['target'] : null;
        $objective = trim((string) ($arguments['objective'] ?? '')) ?: "Run the {$skill} investigation.";

        if (! in_array($skill, HarnessRunner::SKILLS, true)) {
            throw new ToolException('skill must be one of: '.implode(', ', HarnessRunner::SKILLS));
        }

        try {
            $scope = $this->runner->scope();
            $allowed = match ($skill) {
                'port_scan' => $scope->networkTargets(),
                'log_analysis' => $scope->logTargets(),
                default => [],
            };
            if ($skill === 'entry_point') {
                $target = null;
            } elseif ($target === null || ! in_array($target, $allowed, true)) {
                throw new ToolException("{$skill} needs a target from the authorised scope: ".implode(', ', $allowed).'.');
            }

            $run = $this->runner->run($skill, $objective, $target);
        } catch (HarnessException $e) {
            throw new ToolException($e->getMessage(), 0, $e);
        }

        return [
            'planner' => $run->planner,
            'planner_note' => $run->fallbackReason,
            'provider_calls' => $run->summary['provider_calls'] ?? null,
        ] + $this->archive->summary($run->runId);
    }
}
