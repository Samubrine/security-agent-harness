<?php

namespace App\Agent\Tools;

use App\Agent\ApprovalLedger;
use App\Agent\Harness\HarnessException;
use App\Agent\Harness\HarnessRunner;
use App\Agent\Harness\RunArchive;
use App\Agent\Harness\Scope;
use App\Agent\Harness\SkillCatalog;
use App\Models\LogAnalyzer;
use App\Models\SecurityScanner;
use Illuminate\Database\Eloquent\Model;

/**
 * Starts a harness investigation. The skills, their descriptions and their required inputs come
 * from the harness's own skill files, so a new skill YAML is usable here without PHP changes.
 */
class RunInvestigationTool implements AgentTool
{
    public function __construct(
        private readonly HarnessRunner $runner,
        private readonly RunArchive $archive,
        private readonly ApprovalLedger $approvals,
    ) {}

    public function name(): string
    {
        return 'run_investigation';
    }

    public function description(): string
    {
        $skills = collect($this->runner->skills()->all())
            ->map(fn ($s, $name) => "\"{$name}\": {$s['description']}")
            ->implode(' ');

        return 'Start a NEW security investigation with the AEGIS harness against an authorised lab target and return its evidence-backed findings. '
            .'Skills: '.$skills.' '
            .'If the user has not made clear which machine or log source to use, leave `target` out: the harness then asks the user with a form. Never guess. '
            .'Some steps need the operator\'s approval (e.g. calling a third-party MCP server); the result then lists them under approval_needed and the user gets Approve/Decline buttons. '
            .'Takes a few seconds to a minute. Do not re-run an investigation that already answers the question; use get_investigation instead.';
    }

    public function parameters(): array
    {
        $scope = $this->scope();

        return [
            'type' => 'object',
            'properties' => [
                'skill' => ['type' => 'string', 'enum' => $this->runner->skills()->names()],
                'target' => array_filter([
                    'type' => 'string',
                    'enum' => array_values(array_merge($scope->networkTargets(), $scope->logTargets())) ?: null,
                    'description' => 'Scope alias. Network hosts: '.implode(', ', $scope->networkTargets())
                        .'. Log sources: '.implode(', ', $scope->logTargets()).'. Omit for entry_point, or when the user did not say.',
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
            ['scanner_type' => 'network_port', 'engine' => 'harness (nmap / recorded fixtures / MCP)', 'target_scope' => 'signed lab scope', 'version' => 'harness'],
        );
    }

    public function execute(array $arguments): array
    {
        $skill = (string) ($arguments['skill'] ?? '');
        $target = isset($arguments['target']) && $arguments['target'] !== '' ? (string) $arguments['target'] : null;
        $objective = trim((string) ($arguments['objective'] ?? '')) ?: "Run the {$skill} investigation.";
        $catalog = $this->runner->skills();

        if (! in_array($skill, $catalog->names(), true)) {
            throw new ToolException('skill must be one of: '.implode(', ', $catalog->names()));
        }

        try {
            $scope = $this->runner->scope();
            $target = $this->resolveTarget($skill, $target, $catalog->required($skill), $scope, $objective);
            $run = $this->runner->run($skill, $objective, $target, $this->approvals->take($skill, $target));
        } catch (HarnessException $e) {
            throw new ToolException($e->getMessage(), 0, $e);
        }

        return [
            'planner' => $run->planner,
            'planner_note' => $run->fallbackReason,
            'provider_calls' => $run->summary['provider_calls'] ?? null,
            'target' => $target,
        ] + $this->archive->summary($run->runId);
    }

    /**
     * A skill that needs one machine (or one log source) gets it from the request, or the operator
     * is asked. A skill that needs both kinds (entry_point) runs over the whole scope.
     *
     * @param  array<string, string>  $required  input name => type
     */
    private function resolveTarget(string $skill, ?string $target, array $required, Scope $scope, string $objective): ?string
    {
        $types = array_values(array_unique($required));
        if (count($types) !== 1) {
            return null;
        }
        [$options, $label] = match ($types[0]) {
            SkillCatalog::NETWORK => [$scope->networkTargets(), 'Which machine should be checked?'],
            SkillCatalog::FILES => [$scope->logTargets(), 'Which log source should be read?'],
            default => [[], ''],
        };
        if ($target !== null && in_array($target, $options, true)) {
            return $target;
        }
        if ($options === []) {
            throw new ToolException("{$skill} needs a {$types[0]}, and the signed scope has none.");
        }

        throw new NeedsContext(
            skill: $skill,
            objective: $objective,
            fields: [['name' => 'target', 'label' => $label, 'options' => $options]],
            message: ($target === null ? "{$skill} needs a target" : "`{$target}` is not a valid target for {$skill}")
                .'; the operator has been asked to choose one of: '.implode(', ', $options).'. Stop and wait for their answer.',
        );
    }

    private function scope(): Scope
    {
        try {
            return $this->runner->scope();
        } catch (HarnessException) {
            // No signed scope yet: still describe the tool; execute() will explain what is missing.
            return new Scope('missing', []);
        }
    }
}
