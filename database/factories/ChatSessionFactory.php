<?php

namespace Database\Factories;

use App\Models\ChatSession;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<ChatSession>
 */
class ChatSessionFactory extends Factory
{
    protected $model = ChatSession::class;

    public function definition(): array
    {
        $titles = [
            'Autonomous Investigation: DMZ Perimeter Infiltration',
            'Security Audit: Rogue Reverse Shell on Port 4444',
            'Forensic Triage: Suspicious Cron Activity & Base64 Payload',
            'Threat Hunt: Exploit Attempt via CVE-2024-38077',
            'Incident Response: High Volume SSH Failed Logins',
            'Perimeter Scan: Out-of-Scope Asset Discovery Verification',
        ];

        return [
            'user_id' => User::factory(),
            'title' => fake()->randomElement($titles),
            'session_uuid' => (string) Str::uuid(),
            'status' => fake()->randomElement(['active', 'completed', 'archived']),
            'agent_mode' => fake()->randomElement([
                'autonomous_investigation',
                'guided_secops_copilot',
                'strict_compliance_audit',
                'triage_and_containment',
            ]),
        ];
    }
}
