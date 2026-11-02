<?php

namespace App\Agent\Harness;

use Illuminate\Support\Facades\Process;
use Illuminate\Support\Str;

/**
 * Runs the Python investigation harness (src/harness) as a subprocess and reads back what it
 * recorded. The harness keeps all of its own guarantees: signed scope, policy, evidence-bound
 * findings. Laravel only chooses *which* investigation to start.
 */
class HarnessRunner
{
    public const SKILLS = ['port_scan', 'log_analysis', 'entry_point'];

    /**
     * @param  array<string, mixed>  $config  config('agent.harness')
     * @param  array<string, mixed>  $llm  config('agent.llm')
     */
    public function __construct(
        private readonly array $config,
        private readonly array $llm,
    ) {}

    public static function fromConfig(): self
    {
        return new self(config('agent.harness'), config('agent.llm'));
    }

    public function scope(): Scope
    {
        return Scope::load($this->config['scope']);
    }

    public function runsDir(): string
    {
        return $this->config['runs_dir'];
    }

    /**
     * @throws HarnessException
     */
    public function run(string $skill, string $objective, ?string $target = null): HarnessRun
    {
        if (! in_array($skill, self::SKILLS, true)) {
            throw new HarnessException("Unknown skill `{$skill}`.");
        }

        $planner = $this->config['planner'] === 'llm' && $this->llm['api_key'] ? 'llm' : 'scripted';

        if ($planner === 'llm') {
            // A model that cannot produce a valid plan must not cost the user the answer. The
            // harness reports that in two ways: a crash, or a run that ends without completing
            // (e.g. "budget_exhausted" after three unparseable proposals, with zero findings).
            // Either way, rerun with the deterministic planner and say so in the result.
            try {
                $run = $this->invoke($skill, $objective, $target, 'llm');
                if (($run->summary['status'] ?? null) === 'completed') {
                    return $run;
                }
                $why = 'LLM-planned run '.$run->runId.' ended as '.($run->summary['status'] ?? 'unknown')
                    .(isset($run->summary['stop_reason']) ? ': '.$run->summary['stop_reason'] : '');
            } catch (HarnessException $e) {
                $why = 'LLM planner failed: '.$e->getMessage();
            }
            $run = $this->invoke($skill, $objective, $target, 'scripted');

            return new HarnessRun($run->runId, $run->runDir, $run->summary, 'scripted', Str::limit($why, 300));
        }

        return $this->invoke($skill, $objective, $target, 'scripted');
    }

    private function invoke(string $skill, string $objective, ?string $target, string $planner): HarnessRun
    {
        $runId = 'run-'.now()->utc()->format('Ymd\THis').'-'.Str::lower(Str::random(4));
        $runDir = $this->runsDir().DIRECTORY_SEPARATOR.$runId;
        if (! is_dir($this->runsDir())) {
            mkdir($this->runsDir(), 0775, true);
        }

        $command = [
            $this->config['python'], '-m', 'harness.cli', 'run',
            '--skill', $skill,
            '--objective', $objective,
            '--scope', $this->config['scope'],
            '--public-key', $this->config['public_key'],
            '--run-id', $runId,
            '--out', $runDir,
            '--json',
        ];
        if ($target !== null && $target !== '') {
            array_push($command, '--target', $target);
        }

        $env = [
            'PYTHONPATH' => $this->config['root'].DIRECTORY_SEPARATOR.'src',
            'PYTHONIOENCODING' => 'utf-8',
            // Rich wraps output at the terminal width; a wide virtual terminal keeps the JSON intact.
            'COLUMNS' => '400',
        ];
        if ($planner === 'llm') {
            array_push(
                $command,
                '--model-backend', 'openai',
                '--model', $this->llm['model'],
                '--endpoint', $this->llm['base_url'],
                '--allow-remote-egress',
            );
            $env['HARNESS_MODEL_API_KEY'] = (string) $this->llm['api_key'];
        }

        $result = Process::path($this->config['root'])
            ->env($env)
            ->timeout($this->config['timeout'])
            ->run($command);

        $summary = $this->parseSummary($result->output());
        if (! $result->successful() || $summary === null) {
            $why = trim($result->errorOutput()) ?: trim($result->output());
            throw new HarnessException("The harness run failed (exit {$result->exitCode()}): ".Str::limit(preg_replace('/\s+/', ' ', $why), 600));
        }

        return new HarnessRun($summary['run_id'] ?? $runId, $runDir, $summary, $planner);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function parseSummary(string $output): ?array
    {
        $start = strpos($output, '{');
        $end = strrpos($output, '}');
        if ($start === false || $end === false) {
            return null;
        }
        $data = json_decode(substr($output, $start, $end - $start + 1), true);

        return is_array($data) && isset($data['status']) ? $data : null;
    }
}
