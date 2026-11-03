<?php

namespace App\Http\Controllers;

use App\Agent\ApprovalLedger;
use App\Agent\Harness\HarnessException;
use App\Agent\Harness\HarnessRunner;
use App\Agent\Harness\RunArchive;
use App\Agent\Harness\Scope;
use App\Agent\Tools\RunInvestigationTool;
use App\Agent\Tools\ToolException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * The investigation workspace: the harness's recorded runs (findings, evidence, trace, activity,
 * report), the same views as the original local dashboard, now behind the app's login.
 */
class InvestigationController extends Controller
{
    public function index(HarnessRunner $harness): View
    {
        try {
            $scope = $harness->scope();
            $scopeError = null;
        } catch (HarnessException $e) {
            $scope = new Scope('missing', []);
            $scopeError = $e->getMessage();
        }

        return view('investigations.index', compact('scope', 'scopeError'));
    }

    public function runs(RunArchive $archive): JsonResponse
    {
        return response()->json($archive->records());
    }

    public function show(RunArchive $archive, string $run): JsonResponse
    {
        try {
            return response()->json($archive->full($run));
        } catch (HarnessException) {
            abort(404);
        }
    }

    /**
     * Start an investigation directly, without the agent.
     */
    public function store(Request $request, RunInvestigationTool $tool, HarnessRunner $harness, ApprovalLedger $ledger): RedirectResponse
    {
        $validated = $request->validate([
            'skill' => 'required|string|in:'.implode(',', $harness->skills()->names()),
            'target' => 'nullable|string|max:64',
            'objective' => 'nullable|string|max:500',
            'approve' => 'nullable|boolean',
        ]);
        if ($request->boolean('approve')) {
            // Approving up front, for a run started by hand: up to three requests get "yes".
            $ledger->grant($validated['skill'], $validated['target'] ?? null, [true, true, true]);
        }
        unset($validated['approve']);

        set_time_limit(2 * (int) config('agent.harness.timeout') + 30);

        try {
            $result = $tool->execute($validated + ['objective' => $validated['objective'] ?? null]);
        } catch (ToolException $e) {
            return redirect()->route('investigations.index')->withInput()->with('error', $e->getMessage());
        }
        $waiting = count($result['approval_needed'] ?? []);

        $note = $result['planner_note'] ? ' The LLM planner did not finish, so the deterministic planner was used.' : '';

        return redirect()
            ->route('investigations.index', ['run' => $result['run_id'], 'view' => 'overview'])
            ->with('status', 'Investigation '.$result['run_id'].' finished with '.count($result['findings']).' findings.'.$note
                .($waiting ? " {$waiting} step(s) were skipped because they need approval; tick \"approve\" and run again to include them." : ''));
    }
}
