<?php

namespace App\Agent\Harness;

use App\Agent\Progress;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Str;

/**
 * Runs the Python investigation harness (src/harness) as a subprocess and reads back what it
 * recorded. The harness keeps all of its own guarantees: signed scope, policy, evidence-bound
 * findings. Laravel only chooses *which* investigation to start.
 */
class HarnessRunner
{
    /** How often the run's event log is read for live progress, in microseconds. */
    private const POLL_US = 150_000;

    /**
     * @param  array<string, mixed>  $config  config('agent.harness')
     * @param  array<string, mixed>  $llm  config('agent.llm')
     */
    public function __construct(
        private readonly array $config,
        private readonly array $llm,
        private readonly ?Progress $progress = null,
    ) {}

    public static function fromConfig(): self
    {
        return new self(config('agent.harness'), config('agent.llm'), app(Progress::class));
    }

    public function skills(): SkillCatalog
    {
        return new SkillCatalog($this->config['skills_dir'] ?? base_path('src/harness/skills'));
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
    /**
     * @param  list<bool>  $approvals  answers to the harness's approval requests, in order; empty
     *                                 means no human is attached and every request is declined
     */
    public function run(string $skill, string $objective, ?string $target = null, array $approvals = []): HarnessRun
    {
        if (! in_array($skill, $this->skills()->names(), true)) {
            throw new HarnessException("Unknown skill `{$skill}`.");
        }

        $planner = $this->config['planner'] === 'llm' && $this->llm['api_key'] ? 'llm' : 'scripted';

        if ($planner === 'llm') {
            // A model that cannot produce a valid plan must not cost the user the answer. The
            // harness reports that in two ways: a crash, or a run that ends without completing
            // (e.g. "budget_exhausted" after three unparseable proposals, with zero findings).
            // Either way, rerun with the deterministic planner and say so in the result.
            try {
                $run = $this->invoke($skill, $objective, $target, 'llm', $approvals);
                if (($run->summary['status'] ?? null) === 'completed') {
                    return $run;
                }
                $why = 'LLM-planned run '.$run->runId.' ended as '.($run->summary['status'] ?? 'unknown')
                    .(isset($run->summary['stop_reason']) ? ': '.$run->summary['stop_reason'] : '');
            } catch (HarnessException $e) {
                $why = 'LLM planner failed: '.$e->getMessage();
            }
            $run = $this->invoke($skill, $objective, $target, 'scripted', $approvals);

            return new HarnessRun($run->runId, $run->runDir, $run->summary, 'scripted', Str::limit($why, 300));
        }

        return $this->invoke($skill, $objective, $target, 'scripted', $approvals);
    }

    /**
     * @param  list<bool>  $approvals
     */
    private function invoke(string $skill, string $objective, ?string $target, string $planner, array $approvals = []): HarnessRun
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
        if (! empty($this->config['strict'])) {
            $command[] = '--strict';
        }
        $mcp = (string) ($this->config['mcp_config'] ?? '');
        if ($mcp !== '' && is_file($mcp)) {
            array_push($command, '--mcp-config', $mcp);
        }
        if ($approvals !== []) {
            array_push($command, '--approvals', 'scripted', '--approval-answers', implode(',', array_map(fn ($a) => $a ? 'yes' : 'no', $approvals)));
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

        $this->progress?->emit(['type' => 'harness', 'label' => 'Started the harness'.($planner === 'llm' ? ' (AI planner)' : '').' for '.str_replace('_', ' ', $skill).($target ? ' on '.$target : '')]);

        // Started, not run: while it works, its append-only event log is read so the chat can show
        // each step live (scope verified, plan, policy decision, provider started...).
        $process = Process::path($this->config['root'])
            ->env($env)
            ->timeout($this->config['timeout'])
            ->start($command);
        $events = $runDir.DIRECTORY_SEPARATOR.'events.jsonl';
        $offset = 0;
        while ($process->running()) {
            $offset = $this->relayEvents($events, $offset);
            usleep(self::POLL_US);
        }
        $result = $process->wait();
        $this->relayEvents($events, $offset);

        $summary = $this->parseSummary($result->output());
        if (! $result->successful() || $summary === null) {
            $why = trim($result->errorOutput()) ?: trim($result->output());
            throw new HarnessException("The harness run failed (exit {$result->exitCode()}): ".Str::limit(preg_replace('/\s+/', ' ', $why), 600));
        }

        return new HarnessRun($summary['run_id'] ?? $runId, $runDir, $summary, $planner);
    }

    /**
     * Turn new lines of the run's event log into progress events. Returns the new byte offset.
     */
    private function relayEvents(string $file, int $offset): int
    {
        if ($this->progress === null || ! is_file($file)) {
            return $offset;
        }
        clearstatcache(true, $file);
        $size = (int) filesize($file);
        if ($size <= $offset) {
            return $offset;
        }
        $handle = fopen($file, 'rb');
        if ($handle === false) {
            return $offset;
        }
        fseek($handle, $offset);
        $chunk = (string) fread($handle, $size - $offset);
        fclose($handle);
        $complete = strrpos($chunk, "\n");
        if ($complete === false) {
            return $offset; // a line still being written; read it next time
        }
        foreach (explode("\n", substr($chunk, 0, $complete)) as $line) {
            $event = json_decode($line, true);
            if (is_array($event) && ($label = HarnessEvents::label($event)) !== null) {
                $this->progress->emit(['type' => 'harness', 'label' => $label, 'event' => $event['type'] ?? null]);
            }
        }

        return $offset + $complete + 1;
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
