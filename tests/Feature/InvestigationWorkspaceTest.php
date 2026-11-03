<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Tests\TestCase;

class InvestigationWorkspaceTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_workspace_requires_login(): void
    {
        $this->get(route('investigations.index'))->assertRedirect(route('login'));
        $this->getJson(route('investigations.runs'))->assertUnauthorized();
    }

    public function test_the_workspace_page_lists_scope_targets_for_a_new_run(): void
    {
        $this->actingAs(User::factory()->create())
            ->get(route('investigations.index'))
            ->assertOk()
            ->assertSee('Security investigation overview')
            ->assertSee('lab-web-01')
            ->assertSee('lab-logs')
            ->assertSee(route('investigations.runs'), false);
    }

    public function test_it_serves_run_records_in_the_dashboard_format(): void
    {
        $runId = $this->seedRecordedRun();
        $user = User::factory()->create();

        $this->actingAs($user)->getJson(route('investigations.runs'))
            ->assertOk()
            ->assertJsonPath('0.directory', $runId)
            ->assertJsonPath('0.skill', 'port_scan');

        $this->actingAs($user)->getJson(route('investigations.run', $runId))
            ->assertOk()
            ->assertJsonCount(5, 'findings')
            ->assertJsonStructure(['run', 'findings', 'observations', 'events', 'gaps', 'report'])
            ->assertJsonPath('run.skill', 'port_scan');
    }

    public function test_unknown_or_traversing_run_ids_are_not_found(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->getJson('/investigations/runs/run-doesnotexist')->assertNotFound();
        $this->actingAs($user)->getJson('/investigations/runs/..%2F..%2F.env')->assertNotFound();
        $this->actingAs($user)->getJson('/investigations/runs/run-..')->assertNotFound();
    }

    public function test_an_investigation_can_be_started_from_the_workspace(): void
    {
        Process::fake(function (PendingProcess $process) {
            $cmd = $process->command;
            File::copyDirectory(base_path('tests/fixtures/run/port_scan'), $cmd[array_search('--out', $cmd, true) + 1]);

            return Process::result(output: json_encode(['run_id' => $cmd[array_search('--run-id', $cmd, true) + 1], 'status' => 'completed']));
        });

        $response = $this->actingAs(User::factory()->create())
            ->post(route('investigations.store'), ['skill' => 'port_scan', 'target' => 'lab-web-01']);

        $response->assertRedirectContains('/investigations?run=run-');
        $response->assertSessionHas('status', fn ($s) => str_contains($s, '5 findings'));
    }

    public function test_an_out_of_scope_target_is_refused_with_a_message(): void
    {
        Process::fake();

        $this->actingAs(User::factory()->create())
            ->post(route('investigations.store'), ['skill' => 'port_scan', 'target' => '8.8.8.8'])
            ->assertRedirect(route('investigations.index'))
            ->assertSessionHas('error', fn ($e) => str_contains($e, 'lab-web-01'));

        Process::assertNothingRan();
    }
}
