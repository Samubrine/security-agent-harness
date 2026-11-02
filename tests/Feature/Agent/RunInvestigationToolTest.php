<?php

namespace Tests\Feature\Agent;

use App\Agent\Tools\RunInvestigationTool;
use App\Agent\Tools\ToolException;
use App\Models\LogAnalyzer;
use App\Models\SecurityScanner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Tests\TestCase;

class RunInvestigationToolTest extends TestCase
{
    use RefreshDatabase;

    /** Pretend to be the harness: write the recorded run where --out points, print the summary. */
    private function fakeHarness(string $status = 'completed', int $exit = 0): void
    {
        Process::fake(function (PendingProcess $process) use ($status, $exit) {
            $cmd = $process->command;
            $out = $cmd[array_search('--out', $cmd, true) + 1];
            $runId = $cmd[array_search('--run-id', $cmd, true) + 1];
            File::copyDirectory(base_path('tests/fixtures/run/port_scan'), $out);

            return Process::result(
                output: json_encode(['run_id' => $runId, 'run_dir' => $out, 'status' => $status, 'steps' => 3, 'provider_calls' => 2, 'findings' => 5, 'gaps' => 1]),
                exitCode: $exit,
            );
        });
    }

    public function test_it_runs_the_harness_and_returns_findings_most_severe_first(): void
    {
        $this->fakeHarness();

        $result = app(RunInvestigationTool::class)->execute(['skill' => 'port_scan', 'target' => 'lab-web-01', 'objective' => 'Is it safe?']);

        $this->assertSame('scripted', $result['planner']);
        $this->assertCount(5, $result['findings']);
        $this->assertSame('critical', $result['findings'][0]['severity']);
        $this->assertSame(['CVE-2020-1938'], $result['findings'][0]['cves']);
        $this->assertStringStartsWith('run-', $result['run_id']);

        Process::assertRan(fn (PendingProcess $p) => array_slice($p->command, 1, 5) === ['-m', 'harness.cli', 'run', '--skill', 'port_scan']
            && in_array('lab-web-01', $p->command, true)
            && ! in_array('--allow-remote-egress', $p->command, true));
    }

    public function test_the_llm_planner_falls_back_to_scripted_when_the_model_fails(): void
    {
        config(['agent.harness.planner' => 'llm']);
        $attempts = 0;
        Process::fake(function (PendingProcess $process) use (&$attempts) {
            $attempts++;
            if (in_array('--allow-remote-egress', $process->command, true)) {
                return Process::result(errorOutput: 'ModelClientError: could not find a JSON object', exitCode: 2);
            }
            $cmd = $process->command;
            File::copyDirectory(base_path('tests/fixtures/run/port_scan'), $cmd[array_search('--out', $cmd, true) + 1]);

            return Process::result(output: json_encode(['run_id' => $cmd[array_search('--run-id', $cmd, true) + 1], 'status' => 'completed']));
        });

        $result = app(RunInvestigationTool::class)->execute(['skill' => 'port_scan', 'target' => 'lab-web-01', 'objective' => 'x']);

        $this->assertSame(2, $attempts);
        $this->assertSame('scripted', $result['planner']);
        $this->assertStringContainsString('could not find a JSON object', $result['planner_note']);
    }

    public function test_targets_outside_the_scope_are_refused_before_the_harness_runs(): void
    {
        Process::fake();

        try {
            app(RunInvestigationTool::class)->execute(['skill' => 'port_scan', 'target' => '8.8.8.8', 'objective' => 'scan google']);
            $this->fail('expected a ToolException');
        } catch (ToolException $e) {
            $this->assertStringContainsString('lab-web-01', $e->getMessage());
        }
        Process::assertNothingRan();
    }

    public function test_a_log_target_is_refused_for_a_port_scan(): void
    {
        Process::fake();
        $this->expectException(ToolException::class);

        app(RunInvestigationTool::class)->execute(['skill' => 'port_scan', 'target' => 'lab-logs', 'objective' => 'x']);
    }

    public function test_a_failed_harness_run_becomes_a_tool_error(): void
    {
        Process::fake(fn () => Process::result(errorOutput: 'ScopeError: signature does not verify', exitCode: 2));

        $this->expectException(ToolException::class);
        $this->expectExceptionMessage('signature does not verify');

        app(RunInvestigationTool::class)->execute(['skill' => 'entry_point', 'objective' => 'x']);
    }

    public function test_the_log_owner_depends_on_the_skill(): void
    {
        $tool = app(RunInvestigationTool::class);

        $this->assertInstanceOf(LogAnalyzer::class, $tool->loggable(['skill' => 'log_analysis']));
        $this->assertInstanceOf(SecurityScanner::class, $tool->loggable(['skill' => 'port_scan']));
    }
}
