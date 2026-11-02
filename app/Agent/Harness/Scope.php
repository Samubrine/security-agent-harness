<?php

namespace App\Agent\Harness;

/**
 * Read-only view of the signed scope record: which targets the harness is authorised to touch.
 *
 * Laravel only reads it to tell the model what exists and to reject obviously wrong arguments
 * early. The harness verifies the signature and enforces the scope itself on every run.
 */
class Scope
{
    /**
     * @param  array<string, string>  $aliases  alias => "net:10.77.0.11" | "fs:/lab/logs"
     */
    public function __construct(
        public readonly string $scopeId,
        public readonly array $aliases,
        public readonly ?string $notes = null,
    ) {}

    public static function load(string $path): self
    {
        if (! is_file($path)) {
            throw new HarnessException("Signed scope record not found at {$path}. Run `python -m scripts.gen_scope_keypair --skip-if-exists` and `python -m scripts.sign_lab_scope` first.");
        }
        $data = json_decode((string) file_get_contents($path), true);
        if (! is_array($data) || ! isset($data['aliases']) || ! is_array($data['aliases'])) {
            throw new HarnessException("The scope record at {$path} is not valid JSON with an `aliases` map.");
        }

        return new self((string) ($data['scope_id'] ?? 'unknown'), $data['aliases'], $data['notes'] ?? null);
    }

    /** @return list<string> */
    public function networkTargets(): array
    {
        return array_keys(array_filter($this->aliases, fn ($v) => str_starts_with($v, 'net:')));
    }

    /** @return list<string> */
    public function logTargets(): array
    {
        return array_keys(array_filter($this->aliases, fn ($v) => str_starts_with($v, 'fs:')));
    }

    public function describe(): string
    {
        $lines = ["Authorised scope `{$this->scopeId}`:"];
        foreach ($this->aliases as $alias => $address) {
            $kind = str_starts_with($address, 'fs:') ? 'log files' : 'network host';
            $lines[] = "- {$alias} ({$kind})";
        }

        return implode("\n", $lines);
    }
}
