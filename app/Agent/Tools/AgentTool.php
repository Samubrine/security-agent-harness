<?php

namespace App\Agent\Tools;

use Illuminate\Database\Eloquent\Model;

/**
 * A capability the chat agent may call. The model only ever sees name, description and the
 * JSON-schema parameters; Laravel validates the arguments and executes the call.
 */
interface AgentTool
{
    public function name(): string;

    public function description(): string;

    /**
     * JSON schema of the arguments.
     *
     * @return array<string, mixed>
     */
    public function parameters(): array;

    /**
     * The polymorphic owner recorded on the ToolExecutionLog (SecurityScanner, LogAnalyzer,
     * KnowledgeSource...). May depend on the arguments, e.g. a port scan vs a log analysis.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function loggable(array $arguments): Model;

    /**
     * @param  array<string, mixed>  $arguments
     *
     * @throws ToolException for invalid arguments or a failed call; the message is shown to the model
     */
    public function execute(array $arguments): array;
}
