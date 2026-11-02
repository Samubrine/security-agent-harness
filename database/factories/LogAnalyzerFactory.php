<?php

namespace Database\Factories;

use App\Models\LogAnalyzer;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<LogAnalyzer>
 */
class LogAnalyzerFactory extends Factory
{
    protected $model = LogAnalyzer::class;

    public function definition(): array
    {
        $names = [
            'Web Access & SQLi Auditor',
            'Auth Failure & Brute Force Triage',
            'Auditd Kernel Trace Extractor',
            'WAF Anomaly & XSS Stream Processor',
            'Firewall Egress Pattern Correlator',
        ];

        return [
            'name' => fake()->randomElement($names).' #'.fake()->numberBetween(1, 99),
            'log_format' => fake()->randomElement(['apache_combined', 'nginx_json', 'syslog_rfc5424', 'aws_cloudtrail', 'auditd']),
            'pattern_ruleset' => fake()->randomElement(['owasp_crs_v4', 'mitre_attack_v14', 'pci_dss_auth', 'zero_trust_baseline']),
            'severity_threshold' => fake()->randomElement(['info', 'warning', 'critical']),
            'version' => 'v'.fake()->numberBetween(1, 2).'.'.fake()->numberBetween(0, 9).'.'.fake()->numberBetween(0, 9),
        ];
    }
}
