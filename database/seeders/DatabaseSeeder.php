<?php

namespace Database\Seeders;

use App\Models\ChatMessage;
use App\Models\ChatSession;
use App\Models\LogAnalyzer;
use App\Models\MalwareScanner;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // 1. Create Default User (Test Account for easy login)
        $defaultUser = User::firstOrCreate(
            ['email' => 'test@example.com'],
            [
                'name' => 'SecOps Lead Operator',
                'password' => Hash::make('password'),
                'email_verified_at' => now(),
            ]
        );

        // 2. Create Kelompok 6 Member Accounts
        $kelompok6 = [
            ['name' => 'Mikail Ibrahim Hakim', 'nrp' => '5025241046', 'email' => 'mikail@student.its.ac.id'],
            ['name' => 'Fayza Lathifah Humam', 'nrp' => '5025241094', 'email' => 'fayza@student.its.ac.id'],
            ['name' => 'Adriel Mahira Dharma', 'nrp' => '5025241097', 'email' => 'adriel@student.its.ac.id'],
            ['name' => 'Muhammad Adi Anugerah Arrahman', 'nrp' => '5025241118', 'email' => 'adi@student.its.ac.id'],
            ['name' => 'Alfianz Risqia Ilahi Loven Kary', 'nrp' => '5025241164', 'email' => 'alfianz@student.its.ac.id'],
        ];

        foreach ($kelompok6 as $member) {
            User::firstOrCreate(
                ['email' => $member['email']],
                [
                    'name' => $member['name'].' ('.$member['nrp'].')',
                    'password' => Hash::make('password'),
                    'email_verified_at' => now(),
                ]
            );
        }

        // 3. Create Specific Agents for Polymorphic Logging (Challenge 1)
        $securityScanner1 = SecurityScanner::firstOrCreate(
            ['name' => 'AEGIS Nmap Network Scanner'],
            [
                'scanner_type' => 'network_port',
                'engine' => 'nmap-v7.94',
                'target_scope' => '10.0.0.0/24, 192.168.1.0/24',
                'version' => 'v1.2.0',
            ]
        );

        $securityScanner2 = SecurityScanner::firstOrCreate(
            ['name' => 'Vulnerability Surface CVE Mapper'],
            [
                'scanner_type' => 'cve_vulnerability',
                'engine' => 'nuclei-v3.1.8',
                'target_scope' => 'dmz-gateway.corp.local',
                'version' => 'v2.0.4',
            ]
        );

        $malwareScanner1 = MalwareScanner::firstOrCreate(
            ['name' => 'ClamAV Heuristic Threat Engine'],
            [
                'signature_db_version' => 'daily-2026.11.02',
                'heuristic_level' => 'aggressive',
                'engine' => 'clamav-0.105',
                'version' => 'v2.1.0',
            ]
        );

        $malwareScanner2 = MalwareScanner::firstOrCreate(
            ['name' => 'YARA Bytecode Memory Inspector'],
            [
                'signature_db_version' => 'yara-mitre-2026Q4',
                'heuristic_level' => 'paranoid',
                'engine' => 'yara-x-v0.9',
                'version' => 'v3.0.1',
            ]
        );

        $logAnalyzer1 = LogAnalyzer::firstOrCreate(
            ['name' => 'Web Access & OWASP SQLi Auditor'],
            [
                'log_format' => 'apache_combined',
                'pattern_ruleset' => 'owasp_crs_v4.2',
                'severity_threshold' => 'warning',
                'version' => 'v1.4.0',
            ]
        );

        $logAnalyzer2 = LogAnalyzer::firstOrCreate(
            ['name' => 'Auth Failure & Brute Force Triage'],
            [
                'log_format' => 'syslog_rfc5424',
                'pattern_ruleset' => 'mitre_attack_t1110',
                'severity_threshold' => 'critical',
                'version' => 'v1.8.2',
            ]
        );

        // 4. Create Detailed Benchmark Scenario 1 (Web Breach & DMZ Infiltration)
        $session1 = ChatSession::create([
            'user_id' => $defaultUser->id,
            'title' => 'Investigation #1: DMZ Perimeter Infiltration & SQLi Breach Triage',
            'session_uuid' => (string) Str::uuid(),
            'status' => 'active',
            'agent_mode' => 'autonomous_investigation',
        ]);

        $msg1 = ChatMessage::create([
            'chat_session_id' => $session1->id,
            'role' => 'user',
            'content' => 'Operator Alert: High anomaly detected on DMZ web host 192.168.1.50. Run perimeter scan and inspect incoming HTTP requests.',
            'token_count' => 85,
            'sequence_number' => 1,
        ]);

        $msg2 = ChatMessage::create([
            'chat_session_id' => $session1->id,
            'role' => 'assistant',
            'content' => 'Acknowledged. Invoking AEGIS Nmap Network Scanner for port enumeration, followed by OWASP SQLi Analyzer on access logs.',
            'token_count' => 140,
            'sequence_number' => 2,
        ]);

        // Tool Log 1: Polymorphic SecurityScanner
        ToolExecutionLog::create([
            'chat_message_id' => $msg2->id,
            'tool_name' => 'nmap_stealth_scan',
            'status' => 'success',
            'input_parameters' => [
                'target' => '192.168.1.50',
                'ports' => '22,80,443,3306,8080',
                'flags' => '-sS -sV -T4',
            ],
            'output_payload' => [
                'state' => 'up',
                'open_ports' => [
                    ['port' => 80, 'service' => 'http', 'version' => 'Apache/2.4.49'],
                    ['port' => 22, 'service' => 'ssh', 'version' => 'OpenSSH 8.2p1'],
                ],
                'latency_ms' => 14,
            ],
            'execution_time_ms' => 450,
            'loggable_type' => SecurityScanner::class,
            'loggable_id' => $securityScanner1->id,
        ]);

        // Tool Log 2: Polymorphic LogAnalyzer
        ToolExecutionLog::create([
            'chat_message_id' => $msg2->id,
            'tool_name' => 'owasp_sqli_detector',
            'status' => 'success',
            'input_parameters' => [
                'log_path' => '/var/log/apache2/access.log',
                'window_minutes' => 60,
                'filter_patterns' => ['UNION SELECT', 'OR 1=1', 'sleep(5)'],
            ],
            'output_payload' => [
                'threat_events_matched' => 38,
                'source_ips' => ['203.0.113.88', '198.51.100.14'],
                'target_uri' => '/api/v1/auth/login',
                'attack_type' => 'Blind SQL Injection (CWE-89)',
            ],
            'execution_time_ms' => 820,
            'loggable_type' => LogAnalyzer::class,
            'loggable_id' => $logAnalyzer1->id,
        ]);

        $msg3 = ChatMessage::create([
            'chat_session_id' => $session1->id,
            'role' => 'user',
            'content' => 'Attacker dropped a payload in /tmp/cache_sync.bin. Run malware heuristic verification immediately.',
            'token_count' => 60,
            'sequence_number' => 3,
        ]);

        $msg4 = ChatMessage::create([
            'chat_session_id' => $session1->id,
            'role' => 'assistant',
            'content' => 'Deploying ClamAV & YARA bytecode engines to evaluate /tmp/cache_sync.bin.',
            'token_count' => 180,
            'sequence_number' => 4,
        ]);

        // Tool Log 3: Polymorphic MalwareScanner
        ToolExecutionLog::create([
            'chat_message_id' => $msg4->id,
            'tool_name' => 'clamav_heuristic_scan',
            'status' => 'success',
            'input_parameters' => [
                'file_path' => '/tmp/cache_sync.bin',
                'unpack_archive' => true,
                'heuristic_mode' => 'deep',
            ],
            'output_payload' => [
                'verdict' => 'MALICIOUS',
                'threat_name' => 'Trojan.Linux.Mirai.Variant-8',
                'sha256' => '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
                'confidence' => 0.985,
            ],
            'execution_time_ms' => 1240,
            'loggable_type' => MalwareScanner::class,
            'loggable_id' => $malwareScanner1->id,
        ]);

        // Tool Log 4: Polymorphic MalwareScanner (YARA)
        ToolExecutionLog::create([
            'chat_message_id' => $msg4->id,
            'tool_name' => 'yara_memory_verify',
            'status' => 'success',
            'input_parameters' => [
                'ruleset' => 'c2_reverse_shells.yar',
                'pid_target' => 4821,
            ],
            'output_payload' => [
                'matched_rules' => ['Reverse_Shell_TCP', 'Anti_Debugging_Tracer'],
                'c2_callback' => '45.33.32.156:4444',
            ],
            'execution_time_ms' => 610,
            'loggable_type' => MalwareScanner::class,
            'loggable_id' => $malwareScanner2->id,
        ]);

        // 5. Create Detailed Benchmark Scenario 2 (SSH Brute Force Threat Hunt)
        $session2 = ChatSession::create([
            'user_id' => $defaultUser->id,
            'title' => 'Investigation #2: SSH Brute Force & Credential Stuffing Triage',
            'session_uuid' => (string) Str::uuid(),
            'status' => 'completed',
            'agent_mode' => 'triage_and_containment',
        ]);

        $msg5 = ChatMessage::create([
            'chat_session_id' => $session2->id,
            'role' => 'user',
            'content' => 'Audit all authentication failures on gateway node over the past 24 hours.',
            'token_count' => 70,
            'sequence_number' => 1,
        ]);

        $msg6 = ChatMessage::create([
            'chat_session_id' => $session2->id,
            'role' => 'assistant',
            'content' => 'Analyzing /var/log/auth.log via Syslog Auth Analyzer and verifying remote IPs against known botnet CVE hosts.',
            'token_count' => 110,
            'sequence_number' => 2,
        ]);

        ToolExecutionLog::create([
            'chat_message_id' => $msg6->id,
            'tool_name' => 'auth_log_parser',
            'status' => 'success',
            'input_parameters' => [
                'logfile' => '/var/log/auth.log',
                'threshold' => 50,
            ],
            'output_payload' => [
                'failed_attempts' => 1420,
                'unique_usernames' => ['root', 'admin', 'test', 'deploy'],
                'top_attacker' => '185.220.101.5',
            ],
            'execution_time_ms' => 580,
            'loggable_type' => LogAnalyzer::class,
            'loggable_id' => $logAnalyzer2->id,
        ]);

        ToolExecutionLog::create([
            'chat_message_id' => $msg6->id,
            'tool_name' => 'cve_ip_reputation',
            'status' => 'success',
            'input_parameters' => [
                'ip' => '185.220.101.5',
            ],
            'output_payload' => [
                'reputation_score' => 99,
                'classification' => 'Tor Exit Node / SSH Brute Force Actor',
                'recommended_action' => 'IPTables Drop Rule Applied',
            ],
            'execution_time_ms' => 320,
            'loggable_type' => SecurityScanner::class,
            'loggable_id' => $securityScanner2->id,
        ]);

        // 6. Seed Additional Relational Data using Model Factories
        // Creates 3 random sessions with nested messages & polymorphic logs
        ChatSession::factory()
            ->count(3)
            ->for($defaultUser)
            ->create()
            ->each(function (ChatSession $session) use ($securityScanner1, $malwareScanner1, $logAnalyzer1) {
                // Generate 4 messages per session
                for ($seq = 1; $seq <= 4; $seq++) {
                    $isAssistant = ($seq % 2 === 0);
                    $message = ChatMessage::factory()->create([
                        'chat_session_id' => $session->id,
                        'role' => $isAssistant ? 'assistant' : 'user',
                        'sequence_number' => $seq,
                    ]);

                    // Assistant messages execute 1-2 polymorphic tool logs
                    if ($isAssistant) {
                        $agents = [$securityScanner1, $malwareScanner1, $logAnalyzer1];
                        $randomAgent = $agents[array_rand($agents)];

                        ToolExecutionLog::factory()->create([
                            'chat_message_id' => $message->id,
                            'loggable_type' => get_class($randomAgent),
                            'loggable_id' => $randomAgent->id,
                        ]);
                    }
                }
            });
    }
}
