<?php

namespace Database\Seeders;

use App\Agent\Tools\FindingsArchive;
use App\Models\KnowledgeSource;
use App\Models\LogAnalyzer;
use App\Models\SecurityScanner;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Accounts plus the real tool owners the agent logs against. Chat sessions are created by
     * using the app; for the Week 9 N+1 demo data run `php artisan db:seed --class=Week9DemoSeeder`.
     */
    public function run(): void
    {
        User::firstOrCreate(
            ['email' => 'test@example.com'],
            ['name' => 'SecOps Lead Operator', 'password' => Hash::make('password'), 'email_verified_at' => now()],
        );

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
                ['name' => $member['name'].' ('.$member['nrp'].')', 'password' => Hash::make('password'), 'email_verified_at' => now()],
            );
        }

        // The polymorphic owners the agent's tools log against (also created on first use).
        SecurityScanner::firstOrCreate(
            ['name' => 'AEGIS Harness · Service & CVE Scan'],
            ['scanner_type' => 'network_port', 'engine' => 'harness (nmap / recorded fixtures)', 'target_scope' => 'signed lab scope', 'version' => 'harness'],
        );
        LogAnalyzer::firstOrCreate(
            ['name' => 'AEGIS Harness · Log Analysis'],
            ['log_format' => 'syslog_auth + nginx_access', 'pattern_ruleset' => 'harness/rules', 'severity_threshold' => 'medium', 'version' => 'harness'],
        );
        FindingsArchive::source();
        KnowledgeSource::firstOrCreate(
            ['name' => 'NVD CVE Database'],
            ['source_type' => 'public_vulnerability_db', 'provider' => 'NIST', 'endpoint' => config('agent.nvd.base_url')],
        );
    }
}
