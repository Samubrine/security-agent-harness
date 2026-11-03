<?php

namespace App\Providers;

use App\Agent\AgentRunner;
use App\Agent\ApprovalLedger;
use App\Agent\ClaimChecker;
use App\Agent\Progress;
use App\Agent\Harness\HarnessRunner;
use App\Agent\Harness\RunArchive;
use App\Agent\Harness\SkillCatalog;
use App\Agent\LlmClient;
use App\Agent\SystemPrompt;
use App\Agent\ToolRegistry;
use App\Agent\Tools\GetInvestigationTool;
use App\Agent\Tools\ListInvestigationsTool;
use App\Agent\Tools\LookupCveTool;
use App\Agent\Tools\NvdClient;
use App\Agent\Tools\RunInvestigationTool;
use App\Agent\Tools\SearchCvesTool;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // One per request: the live progress channel and the operator's approvals for the next run.
        $this->app->singleton(Progress::class);
        $this->app->singleton(ApprovalLedger::class);
        $this->app->singleton(LlmClient::class, fn () => LlmClient::fromConfig());
        $this->app->singleton(HarnessRunner::class, fn () => HarnessRunner::fromConfig());
        $this->app->singleton(RunArchive::class, fn () => RunArchive::fromConfig());
        $this->app->bind(SkillCatalog::class, fn () => SkillCatalog::fromConfig());
        $this->app->singleton(NvdClient::class, fn () => NvdClient::fromConfig());

        // The agent's toolbox. Adding a capability = one AgentTool class + one line here.
        $this->app->singleton(ToolRegistry::class, fn (Application $app) => new ToolRegistry([
            $app->make(RunInvestigationTool::class),
            $app->make(ListInvestigationsTool::class),
            $app->make(GetInvestigationTool::class),
            $app->make(LookupCveTool::class),
            $app->make(SearchCvesTool::class),
        ]));

        $this->app->bind(AgentRunner::class, fn (Application $app) => new AgentRunner(
            llm: $app->make(LlmClient::class),
            tools: $app->make(ToolRegistry::class),
            systemPrompt: $app->make(SystemPrompt::class),
            maxSteps: (int) config('agent.max_steps'),
            historyMessages: (int) config('agent.history_messages'),
            toolMode: (string) config('agent.llm.tool_mode'),
            progress: $app->make(Progress::class),
            claims: $app->make(ClaimChecker::class),
        ));
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // PHP on Windows often ships without a CA bundle (cURL error 60). scripts/setup.py downloads
        // one and sets AGENT_CA_BUNDLE, so teammates never have to edit php.ini.
        $bundle = config('agent.ca_bundle');
        if ($bundle && is_file($bundle)) {
            Http::globalOptions(['verify' => $bundle]);
        }
    }
}
