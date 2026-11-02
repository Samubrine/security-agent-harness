<?php

namespace App\Agent\Tools;

use Illuminate\Database\Eloquent\Model;

class LookupCveTool implements AgentTool
{
    public function __construct(private readonly NvdClient $nvd) {}

    public function name(): string
    {
        return 'lookup_cve';
    }

    public function description(): string
    {
        return 'Look up one CVE in the public NIST National Vulnerability Database: description, CVSS score and severity, weakness type (CWE), '
            .'whether it is known to be exploited in the wild (CISA KEV), and patch/advisory links. '
            .'Use it to explain or prioritise CVEs that an investigation reported.';
    }

    public function parameters(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'cve_id' => ['type' => 'string', 'description' => 'e.g. CVE-2021-41773'],
            ],
            'required' => ['cve_id'],
        ];
    }

    public function loggable(array $arguments): Model
    {
        return $this->nvd->source();
    }

    public function execute(array $arguments): array
    {
        $id = strtoupper(trim((string) ($arguments['cve_id'] ?? '')));
        if (! preg_match('/^CVE-\d{4}-\d{4,7}$/', $id)) {
            throw new ToolException('cve_id must look like CVE-2021-41773.');
        }

        return $this->nvd->cve($id) ?? ['id' => $id, 'found' => false, 'note' => 'NVD has no record of this CVE id.'];
    }
}
