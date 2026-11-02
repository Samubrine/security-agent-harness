<?php

namespace Database\Factories;

use App\Models\ChatMessage;
use App\Models\ChatSession;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ChatMessage>
 */
class ChatMessageFactory extends Factory
{
    protected $model = ChatMessage::class;

    public function definition(): array
    {
        $userPrompts = [
            'Scan target 192.168.1.50 for open ports and identify outdated Apache services.',
            'Check /var/log/auth.log for repeated sudo authentication failures in the last 2 hours.',
            'Analyze file sample_drop.bin extracted from quarantine for malicious payload signatures.',
            'Correlate web access logs with known CVE-2023-4863 signatures to see if we were targeted.',
        ];

        $assistantResponses = [
            'Target analysis initiated. Proposing nmap port scan with default security necessity gate policy.',
            'Execution completed: Found open port 80/tcp (Apache 2.4.49) and port 22/tcp (OpenSSH 8.2p1). Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773).',
            'Extracted 14,290 log lines. Detected 127 failed password attempts from IP 203.0.113.45 targeting user root.',
            'Malware heuristic scan flagged binary with 94.2% confidence. YARA rule Backdoor.Linux.Mirai.Gen matched at offset 0x0001a4.',
        ];

        $role = fake()->randomElement(['user', 'assistant']);
        $content = $role === 'user' ? fake()->randomElement($userPrompts) : fake()->randomElement($assistantResponses);

        return [
            'chat_session_id' => ChatSession::factory(),
            'role' => $role,
            'content' => $content,
            'token_count' => fake()->numberBetween(45, 1250),
            'sequence_number' => 1,
        ];
    }
}
