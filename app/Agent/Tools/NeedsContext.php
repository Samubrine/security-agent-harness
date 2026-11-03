<?php

namespace App\Agent\Tools;

/**
 * A skill needs an input the request did not supply (which machine? which logs?). Raised by a tool
 * instead of letting the model guess; the runner stops and shows the operator a form whose options
 * come from the signed scope, never from the model.
 */
class NeedsContext extends ToolException
{
    /**
     * @param  list<array{name: string, label: string, options: list<string>}>  $fields
     */
    public function __construct(
        public readonly string $skill,
        public readonly string $objective,
        public readonly array $fields,
        string $message,
    ) {
        parent::__construct($message);
    }
}
