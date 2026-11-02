<?php

namespace App\Support;

use App\Models\ToolExecutionLog;

/**
 * Plain-language wording for what the agent does and finds. The technical names (tool names,
 * severities, finding statuses) stay in the data; this is only what a non-expert reads first.
 */
final class Plain
{
    private const SEVERITY = [
        'critical' => ['Fix now', 'Attackers can probably take over the machine'],
        'high' => ['Fix soon', 'Serious weakness that should be patched'],
        'medium' => ['Worth a look', 'Weaker risk, or something suspicious'],
        'low' => ['Minor', 'Small risk'],
        'info' => ['For your information', 'No action needed'],
    ];

    /** @return array{0: string, 1: string} short label and one-line meaning */
    public static function severity(?string $severity): array
    {
        return self::SEVERITY[strtolower((string) $severity)] ?? self::SEVERITY['info'];
    }

    /**
     * A finding title a beginner can read. The original title stays in the technical details.
     */
    public static function findingTitle(?string $title): string
    {
        $title = (string) $title;
        if (preg_match('/^(.+?) is inside the range of (CVE-\d{4}-\d+)$/i', $title, $m)) {
            return $m[1].' has a known security flaw ('.$m[2].')';
        }
        if (stripos($title, 'instruction-shaped content') !== false) {
            return 'Text aimed at tricking AI tools was found in the server\'s data (it was blocked)';
        }

        return $title;
    }

    public static function status(?string $status): string
    {
        return match ($status) {
            'confirmed' => 'Confirmed by evidence',
            'possible' => 'Likely, not yet confirmed',
            default => ucfirst((string) $status),
        };
    }

    /**
     * What the agent did, as a sentence a beginner understands.
     */
    public static function toolTitle(ToolExecutionLog $log): string
    {
        $in = $log->input_parameters ?? [];
        $target = $in['target'] ?? null;

        return match ($log->tool_name) {
            'run_investigation' => match ($in['skill'] ?? '') {
                'port_scan' => 'Scanned '.($target ?? 'the lab').' for open services and outdated software',
                'log_analysis' => 'Read the logs of '.($target ?? 'the lab').' looking for signs of an attack',
                'entry_point' => 'Worked out how an attacker could get into '.($target ?? 'the lab'),
                default => 'Ran a security investigation',
            },
            'lookup_cve' => 'Looked up '.($in['cve_id'] ?? 'a vulnerability').' in the public vulnerability database',
            'search_cves' => 'Searched the public vulnerability database for “'.($in['keyword'] ?? '').'”',
            'list_investigations' => 'Checked what earlier investigations had found',
            'get_investigation' => 'Re-read the details of an earlier investigation',
            default => 'Used the tool '.$log->tool_name,
        };
    }

    /**
     * Why the agent says it made the call: its own sentence if it wrote one, else a fixed one.
     */
    public static function toolReason(ToolExecutionLog $log): string
    {
        if (filled($log->rationale)) {
            return $log->rationale;
        }

        return match ($log->tool_name) {
            'run_investigation' => 'Evidence has to come from a real check, not from guessing.',
            'lookup_cve', 'search_cves' => 'The public database says how dangerous a flaw is and whether attackers already use it.',
            'list_investigations', 'get_investigation' => 'Earlier results can answer this without scanning again.',
            default => '',
        };
    }

    /**
     * The result of a call, in one line.
     */
    public static function toolOutcome(ToolExecutionLog $log): string
    {
        $out = $log->output_payload ?? [];
        if ($log->status !== 'success') {
            return 'Did not run: '.($out['error'] ?? 'it failed').'.';
        }

        return match ($log->tool_name) {
            'run_investigation' => self::findingsLine($out['findings'] ?? [])
                .(($out['planner'] ?? '') === 'scripted' && ! empty($out['planner_note']) ? ' (AI planning failed, so it used the built-in checklist)' : ''),
            'lookup_cve' => isset($out['cvss_score'])
                ? ucfirst(strtolower($out['severity'] ?? '')).' danger, '.$out['cvss_score'].' out of 10'
                    .(! empty($out['known_exploited']) ? ', and attackers are already using it' : '')
                : 'No details found.',
            'search_cves' => ($out['count'] ?? 0).' matching vulnerabilities found',
            'list_investigations' => ($out['count'] ?? 0).' earlier investigations on record',
            'get_investigation' => count($out['findings'] ?? []).' problems in that investigation',
            default => 'Done',
        };
    }

    /**
     * @param  list<array<string, mixed>>  $findings
     */
    public static function findingsLine(array $findings): string
    {
        if ($findings === []) {
            return 'Found no problems';
        }
        $counts = collect($findings)->countBy(fn ($f) => $f['severity'] ?? 'info');
        $serious = ($counts['critical'] ?? 0) + ($counts['high'] ?? 0);
        $line = 'Found '.count($findings).' '.(count($findings) === 1 ? 'problem' : 'problems');

        return $serious > 0 ? $line.', '.$serious.' serious' : $line;
    }

    /**
     * Overall traffic light for a set of findings.
     *
     * @param  array<string, int>  $counts  severity => number
     * @return array{level: string, headline: string, detail: string}
     */
    public static function verdict(array $counts, bool $checked): array
    {
        if (! $checked) {
            return ['level' => 'unknown', 'headline' => 'Not checked yet', 'detail' => 'Run a check-up and the agent will tell you where you stand.'];
        }
        $critical = $counts['critical'] ?? 0;
        $high = $counts['high'] ?? 0;
        if ($critical > 0) {
            return ['level' => 'critical', 'headline' => 'Needs attention', 'detail' => $critical.' critical '.($critical === 1 ? 'problem' : 'problems').' could let an attacker in.'];
        }
        if ($high > 0) {
            return ['level' => 'high', 'headline' => 'Fix soon', 'detail' => $high.' serious '.($high === 1 ? 'weakness' : 'weaknesses').' should be patched.'];
        }
        if (array_sum($counts) > 0) {
            return ['level' => 'medium', 'headline' => 'Mostly fine', 'detail' => 'Only minor things were found.'];
        }

        return ['level' => 'ok', 'headline' => 'No known problems', 'detail' => 'The last checks found nothing.'];
    }
}
