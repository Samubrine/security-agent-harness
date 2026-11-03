<?php

namespace App\Agent;

/**
 * Approvals the operator gave for the next harness run of a given skill and target.
 *
 * The harness asks a human before risky calls ("ask" verdicts). A web request cannot keep a
 * subprocess waiting for a click, so the first run fails closed (the call is declined and
 * recorded as a gap), the operator sees what was asked, and an approval is stored here for the
 * rerun. The answers are consumed once and passed to the harness as scripted answers in request
 * order; a request the operator never saw still gets "no" (the harness denies when answers run
 * out).
 */
class ApprovalLedger
{
    /** @var array<string, list<bool>> */
    private array $answers = [];

    /**
     * @param  list<bool>  $answers
     */
    public function grant(string $skill, ?string $target, array $answers): void
    {
        $this->answers[$this->key($skill, $target)] = array_values($answers);
    }

    /**
     * @return list<bool>
     */
    public function take(string $skill, ?string $target): array
    {
        $key = $this->key($skill, $target);
        $answers = $this->answers[$key] ?? [];
        unset($this->answers[$key]);

        return $answers;
    }

    private function key(string $skill, ?string $target): string
    {
        return $skill.'|'.($target ?? '*');
    }
}
