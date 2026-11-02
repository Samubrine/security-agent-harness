<?php

namespace Database\Factories;

use App\Models\KnowledgeSource;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<KnowledgeSource>
 */
class KnowledgeSourceFactory extends Factory
{
    protected $model = KnowledgeSource::class;

    public function definition(): array
    {
        return fake()->randomElement([
            ['name' => 'NVD CVE Database', 'source_type' => 'public_vulnerability_db', 'provider' => 'NIST', 'endpoint' => 'https://services.nvd.nist.gov/rest/json/cves/2.0'],
            ['name' => 'AEGIS Findings Archive', 'source_type' => 'internal_findings', 'provider' => 'security-agent-harness', 'endpoint' => null],
        ]);
    }
}
