<?php

namespace App\Agent;

use App\Agent\Tools\AgentTool;

class ToolRegistry
{
    /** @var array<string, AgentTool> */
    private array $tools = [];

    /**
     * @param  iterable<AgentTool>  $tools
     */
    public function __construct(iterable $tools)
    {
        foreach ($tools as $tool) {
            $this->tools[$tool->name()] = $tool;
        }
    }

    public function get(string $name): ?AgentTool
    {
        return $this->tools[$name] ?? null;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->tools);
    }

    /**
     * OpenAI `tools` parameter.
     *
     * @return list<array<string, mixed>>
     */
    public function schemas(): array
    {
        return array_values(array_map(fn (AgentTool $t) => [
            'type' => 'function',
            'function' => [
                'name' => $t->name(),
                'description' => $t->description(),
                'parameters' => $t->parameters(),
            ],
        ], $this->tools));
    }
}
