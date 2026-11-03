<?php

namespace App\Agent\Harness;

/**
 * The harness skills, read from their YAML files (src/harness/skills/*.yaml).
 *
 * The chat agent's `run_investigation` tool is generated from this, so adding a skill to the
 * harness (one YAML file) also makes it available in the chat without PHP changes. Only the few
 * top-level fields the web app needs are read: name, description and the declared inputs.
 */
class SkillCatalog
{
    /** Input types a skill can declare, and which scope aliases satisfy them. */
    public const NETWORK = 'scope_target';

    public const FILES = 'scope_fs_target';

    public function __construct(private readonly string $dir) {}

    public static function fromConfig(): self
    {
        return new self(config('agent.harness.skills_dir'));
    }

    /**
     * @return array<string, array{description: string, inputs: array<string, array{type: string, required: bool}>}>
     */
    public function all(): array
    {
        $skills = [];
        foreach (glob($this->dir.DIRECTORY_SEPARATOR.'*.yaml') ?: [] as $file) {
            $skill = $this->parse((string) file_get_contents($file));
            if ($skill['name'] !== '') {
                $skills[$skill['name']] = ['description' => $skill['description'], 'inputs' => $skill['inputs']];
            }
        }
        ksort($skills);

        return $skills;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->all());
    }

    /**
     * Required input types of a skill, e.g. ['target' => 'scope_target'].
     *
     * @return array<string, string>
     */
    public function required(string $skill): array
    {
        $inputs = $this->all()[$skill]['inputs'] ?? [];

        return array_map(fn ($i) => $i['type'], array_filter($inputs, fn ($i) => $i['required']));
    }

    /**
     * @return array{name: string, description: string, inputs: array<string, array{type: string, required: bool}>}
     */
    private function parse(string $yaml): array
    {
        $name = '';
        $description = '';
        $inputs = [];
        $section = null;
        $current = null;
        foreach (preg_split('/\R/', $yaml) ?: [] as $line) {
            if (preg_match('/^(\w+):\s*(.*)$/', $line, $m)) {
                $section = $m[1];
                if ($m[1] === 'name') {
                    $name = trim($m[2], " '\"");
                } elseif ($m[1] === 'description') {
                    $description = trim($m[2], " '\"");
                }

                continue;
            }
            if ($section !== 'inputs') {
                continue;
            }
            if (preg_match('/^  (\w+):\s*$/', $line, $m)) {
                $current = $m[1];
                $inputs[$current] = ['type' => '', 'required' => false];
            } elseif ($current !== null && preg_match('/^    (type|required):\s*(\S+)/', $line, $m)) {
                $inputs[$current][$m[1]] = $m[1] === 'required' ? strtolower($m[2]) === 'true' : $m[2];
            }
        }

        return ['name' => $name, 'description' => $description, 'inputs' => $inputs];
    }
}
