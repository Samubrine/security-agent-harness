<?php

namespace Database\Factories;

use App\Models\ChatMessage;
use App\Models\LogAnalyzer;
use App\Models\MalwareScanner;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ToolExecutionLog>
 */
class ToolExecutionLogFactory extends Factory
{
    protected $model = ToolExecutionLog::class;

    public function definition(): array
    {
        $tools = [
            'nmap_port_sweep' => [
                'input' => ['target' => '192.168.1.50/24', 'ports' => '21,22,80,443,8080', 'timing' => '-T4'],
                'output' => ['hosts_up' => 3, 'open_ports' => [80, 443], 'latency_ms' => 12],
            ],
            'yara_memory_matcher' => [
                'input' => ['pid' => 1337, 'ruleset' => 'webshells_and_miners.yar'],
                'output' => ['matches' => ['PHP_Eval_Exploit', 'CryptoMiner_Pool_String'], 'risk' => 'critical'],
            ],
            'access_log_sqli_scanner' => [
                'input' => ['log_path' => '/var/log/nginx/access.log', 'regex_profile' => 'union_select_blind'],
                'output' => ['attempts_found' => 14, 'attacker_ips' => ['198.51.100.22'], 'blocked_by_waf' => true],
            ],
            'cve_vulnerability_correlator' => [
                'input' => ['service' => 'OpenSSH', 'version' => '8.2p1', 'cve_db' => 'NVD-2026'],
                'output' => ['known_cves' => ['CVE-2020-15778'], 'exploitability_score' => 6.8],
            ],
        ];

        $toolKey = fake()->randomElement(array_keys($tools));
        $toolData = $tools[$toolKey];

        // Polymorphic assignment
        $agentTypes = [
            SecurityScanner::class,
            MalwareScanner::class,
            LogAnalyzer::class,
        ];
        $agentClass = fake()->randomElement($agentTypes);

        return [
            'chat_message_id' => ChatMessage::factory(),
            'tool_name' => $toolKey,
            'status' => fake()->randomElement(['success', 'success', 'success', 'failed']),
            'input_parameters' => $toolData['input'],
            'output_payload' => $toolData['output'],
            'execution_time_ms' => fake()->numberBetween(15, 3400),
            'loggable_type' => $agentClass,
            'loggable_id' => $agentClass::factory(),
        ];
    }
}
