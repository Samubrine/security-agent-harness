<?php

namespace App\Agent;

/**
 * Live progress of one agent turn. The runner and the harness emit small events here; the chat
 * page receives them as a stream while the turn is still running. With no listener attached
 * (tests, the non-JavaScript fallback) emitting is a no-op.
 */
class Progress
{
    /** @var (callable(array<string, mixed>): void)|null */
    private $listener = null;

    public function listen(?callable $listener): void
    {
        $this->listener = $listener;
    }

    /**
     * @param  array<string, mixed>  $event
     */
    public function emit(array $event): void
    {
        if ($this->listener !== null) {
            ($this->listener)($event);
        }
    }
}
