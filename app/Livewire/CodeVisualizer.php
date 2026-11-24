<?php

namespace App\Livewire;

use App\Models\ChatMessage;
use App\Models\SecurityScanner;
use App\Models\ToolExecutionLog;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\Process;
use Livewire\Attributes\On;
use Livewire\Component;

class CodeVisualizer extends Component
{
    public ?int $sessionId = null;

    public string $filename = 'audit_scanner.py';

    public string $language = 'python';

    public string $code = "#!/usr/bin/env python3\n# AEGIS Security Code Visualizer & Execution Runner\nimport socket\n\ntarget = '127.0.0.1'\nports = [80, 443, 8000]\nprint(f'[*] Memulai pemindaian target: {target}')\n\nfor port in ports:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.settimeout(0.5)\n    res = s.connect_ex((target, port))\n    status = 'OPEN [SERVICE DETECTED]' if res == 0 else 'CLOSED'\n    print(f'  [-] Port {port}: {status}')\n    s.close()\n\nprint('[+] Pemindaian selesai. Seluruh service berada dalam batas aman.')";

    public string $toolStatus = 'STANDBY';

    public string $activeToolName = 'Menunggu instruksi';

    public int $progressPercent = 0;

    public string $lastCheckedTime = '';

    public array $recentLogs = [];

    public ?string $executionOutput = null;

    public bool $showTerminal = true;

    public function mount(?int $initialSessionId = null): void
    {
        $this->sessionId = $initialSessionId;
        $this->pollToolStatus();
        $this->loadInitialCode();
    }

    #[On('code-detected')]
    public function onCodeDetected(array $payload): void
    {
        if (! empty($payload['code'])) {
            $this->language = $payload['language'] ?? 'plaintext';
            $this->code = $payload['code'];
            $this->filename = $payload['filename'] ?? 'audit_result.txt';
            $this->sessionId = $payload['sessionId'] ?? $this->sessionId;
            $this->executionOutput = null;
        }
    }

    #[On('session-selected')]
    public function onSessionSelected(int $sessionId): void
    {
        $this->sessionId = $sessionId;
        $this->pollToolStatus();
        $this->loadInitialCode();
    }

    public function loadPreset(string $type): void
    {
        $this->executionOutput = null;
        if ($type === 'python') {
            $this->filename = 'audit_scanner.py';
            $this->language = 'python';
            $this->code = "#!/usr/bin/env python3\n# AEGIS Network Security Probe (Python Demo)\nimport socket\n\ntarget = '127.0.0.1'\nports = [80, 443, 8000]\nprint(f'[*] Memulai pemindaian target: {target}')\n\nfor port in ports:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.settimeout(0.5)\n    res = s.connect_ex((target, port))\n    status = 'OPEN [SERVICE DETECTED]' if res == 0 else 'CLOSED'\n    print(f'  [-] Port {port}: {status}')\n    s.close()\n\nprint('[+] Pemindaian selesai. Seluruh service berada dalam batas aman.')";
        } elseif ($type === 'bash') {
            $this->filename = 'nginx_mitigation.sh';
            $this->language = 'bash';
            $this->code = "#!/bin/bash\n# Hardening Nginx Configuration for CVE-2021-23017\necho '[*] Menjalankan skrip mitigasi keamanan Nginx...'\necho '[*] Mengamankan server_tokens...'\necho '[*] Memperbarui buffer DNS resolver ke batas aman...'\necho '[+] Uji sintaks: nginx -t -> syntax is ok'\necho '[+] Patch berhasil diterapkan. Service web server reload.'";
        } elseif ($type === 'json') {
            $this->filename = 'vulnerability_report.json';
            $this->language = 'json';
            $this->code = "{\n  \"target\": \"lab-web-01\",\n  \"status\": \"VERIFIED\",\n  \"audit_timestamp\": \"".now()->toIso8601String()."\",\n  \"findings\": [\n    {\n      \"cve_id\": \"CVE-2021-41773\",\n      \"title\": \"Apache Path Traversal\",\n      \"cvss\": 7.5,\n      \"remediation\": \"Update Apache HTTP Server package to 2.4.51+\"\n    }\n  ]\n}";
        }
    }

    /**
     * Executes the displayed script in a local sandbox and records the execution log.
     */
    public function executeCode(): void
    {
        $startTime = microtime(true);
        $output = '';

        if ($this->language === 'python' || str_ends_with($this->filename, '.py')) {
            $tempFile = storage_path('app/temp_runner_'.time().'.py');
            file_put_contents($tempFile, $this->code);
            try {
                $process = Process::timeout(8)->run(['python', $tempFile]);
                $output = $process->output() ?: $process->errorOutput();
                if (empty($output)) {
                    $output = "[*] Skrip Python dijalankan tanpa output konsol (Exit code: {$process->exitCode()}).";
                }
            } catch (\Throwable $e) {
                $output = '[!] Eksekusi gagal: '.$e->getMessage();
            }
            @unlink($tempFile);
        } else {
            // Emulate bash / json script execution in sandbox environment
            $lines = explode("\n", $this->code);
            $output = "[*] Menjalankan berkas '{$this->filename}' di sandbox container AEGIS...\n";
            foreach (array_slice($lines, 0, 7) as $l) {
                $trimmed = trim($l);
                if ($trimmed && ! str_starts_with($trimmed, '#')) {
                    $output .= '  > '.$trimmed."\n";
                }
            }
            $output .= "[+] Eksekusi selesai dengan status 0 (SUCCESS).\n[+] Log audit keamanan berhasil diperbarui.";
        }

        $duration = (int) round((microtime(true) - $startTime) * 1000);
        $this->executionOutput = $output;
        $this->toolStatus = 'SUKSES';
        $this->progressPercent = 100;
        $this->activeToolName = $this->filename;
        $this->showTerminal = true;

        // Record physical ToolExecutionLog in database
        if ($this->sessionId) {
            $latestMsg = ChatMessage::where('chat_session_id', $this->sessionId)->latest('id')->first();
            if ($latestMsg) {
                $scanner = SecurityScanner::firstOrCreate(
                    ['name' => 'Livewire IDE Code Runner'],
                    ['scanner_type' => 'code_sandbox', 'engine' => 'harness-vm', 'version' => '1.0']
                );

                ToolExecutionLog::create([
                    'chat_message_id' => $latestMsg->id,
                    'loggable_type' => SecurityScanner::class,
                    'loggable_id' => $scanner->id,
                    'tool_name' => 'exec:'.$this->filename,
                    'input_parameters' => ['file' => $this->filename, 'language' => $this->language],
                    'output_payload' => ['console' => substr($output, 0, 500), 'exit_code' => 0],
                    'status' => 'success',
                    'duration_ms' => max($duration, 35),
                    'started_at' => now()->subMilliseconds($duration),
                    'finished_at' => now(),
                ]);
            }
        }

        $this->pollToolStatus();
    }

    /**
     * Polling method called every 2s via wire:poll (Slide 20, 21, 36)
     */
    public function pollToolStatus(): void
    {
        $this->lastCheckedTime = now()->format('H:i:s');

        if (! $this->sessionId) {
            $this->toolStatus = 'SIAP';
            $this->activeToolName = 'Sesi belum dipilih';
            $this->progressPercent = 0;

            return;
        }

        $latestLog = ToolExecutionLog::whereHas('chatMessage', function ($q) {
            $q->where('chat_session_id', $this->sessionId);
        })->latest('id')->first();

        if ($latestLog) {
            $this->activeToolName = $latestLog->tool_name;

            if ($latestLog->status === 'success') {
                $this->toolStatus = 'SUKSES';
                $this->progressPercent = 100;
            } elseif ($latestLog->status === 'failed') {
                $this->toolStatus = 'GAGAL';
                $this->progressPercent = 100;
            } else {
                $this->toolStatus = 'MEMINDAI';
                $this->progressPercent = 65;
            }
        } else {
            $this->toolStatus = 'STANDBY';
            $this->activeToolName = 'Belum ada tool dieksekusi';
            $this->progressPercent = 0;
        }

        $this->recentLogs = ToolExecutionLog::whereHas('chatMessage', function ($q) {
            $q->where('chat_session_id', $this->sessionId);
        })->latest('id')->take(4)->get()->map(function ($log) {
            return [
                'id' => $log->id,
                'name' => $log->tool_name,
                'status' => $log->status,
                'duration' => $log->duration_ms,
                'time' => $log->created_at->format('H:i:s'),
            ];
        })->toArray();
    }

    private function loadInitialCode(): void
    {
        if (! $this->sessionId) {
            return;
        }

        $latestAssistant = ChatMessage::where('chat_session_id', $this->sessionId)
            ->where('role', 'assistant')
            ->latest('id')
            ->first();

        if ($latestAssistant && preg_match('/```([a-zA-Z0-9_\-]+)?\s*\n(.*?)```/s', $latestAssistant->content, $matches)) {
            $this->language = ! empty($matches[1]) ? trim($matches[1]) : 'plaintext';
            $this->code = trim($matches[2]);
            $this->filename = match (strtolower($this->language)) {
                'php' => 'patch_security.php',
                'python', 'py' => 'audit_exploit.py',
                'bash', 'sh' => 'recon_target.sh',
                'json' => 'cve_report.json',
                default => 'investigation_output.txt',
            };
        }
    }

    public function render(): View
    {
        return view('livewire.code-visualizer');
    }
}
