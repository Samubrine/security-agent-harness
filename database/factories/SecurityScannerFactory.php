<?php

namespace Database\Factories;

use App\Models\SecurityScanner;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SecurityScanner>
 */
class SecurityScannerFactory extends Factory
{
    protected $model = SecurityScanner::class;

    public function definition(): array
    {
        $names = [
            'AEGIS Nmap Network Scanner',
            'Vulnerability Surface Mapper',
            'Subdomain & DNS Recon Agent',
            'Port Sweep & Service Fingerprinter',
            'SSL/TLS Configuration Auditor',
        ];

        return [
            'name' => fake()->randomElement($names).' #'.fake()->numberBetween(1, 99),
            'scanner_type' => fake()->randomElement(['network_port', 'vulnerability_cve', 'service_banner', 'tls_audit']),
            'engine' => fake()->randomElement(['nmap-v7.94', 'masscan-v1.3', 'nuclei-v3.1', 'testssl-v3.0']),
            'target_scope' => fake()->randomElement(['10.0.0.0/24', '192.168.1.0/24', 'corp.internal.net', 'api.target-lab.local']),
            'version' => 'v'.fake()->numberBetween(1, 3).'.'.fake()->numberBetween(0, 9).'.'.fake()->numberBetween(0, 9),
        ];
    }
}
