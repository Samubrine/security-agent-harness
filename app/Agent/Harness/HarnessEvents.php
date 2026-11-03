<?php

namespace App\Agent\Harness;

/**
 * Plain-language labels for the harness's own event types, for live progress. Events that are
 * too fine-grained to be useful one by one (each observation, claim or memory write) return null.
 */
class HarnessEvents
{
    /**
     * @param  array<string, mixed>  $event  one line of events.jsonl
     */
    public static function label(array $event): ?string
    {
        $d = is_array($event['data'] ?? null) ? $event['data'] : [];
        $provider = self::provider((string) ($d['provider'] ?? ''));

        return match ($event['type'] ?? '') {
            'AUTHORITY_VERIFIED' => 'Verified the signed scope (who authorised this, which machines)',
            'CONTEXT_RESOLVED' => 'Resolved what to investigate',
            'PLAN_PROPOSED' => 'Planner chose the next information need',
            'NECESSITY_DECIDED' => isset($d['selected']) && is_array($d['selected']) && $d['selected'] !== []
                ? 'Necessity gate: use '.implode(' + ', array_map([self::class, 'provider'], $d['selected']))
                    .(($d['expansion_reason'] ?? null) === 'trust_diversity' ? ' (two independent sources required)' : '')
                : 'Necessity gate: nothing more is needed',
            'POLICY_DECIDED' => 'Policy: '.match ($d['verdict'] ?? '') {
                'allow' => 'allowed', 'ask' => 'needs approval for', 'deny' => 'refused', default => (string) ($d['verdict'] ?? ''),
            }.' '.$provider,
            'APPROVAL_REQUESTED' => 'Asked for your approval to use '.$provider,
            'APPROVAL_GIVEN' => ! empty($d['approved']) ? 'Approved' : 'Not approved, so that step was skipped',
            'PROVIDER_STARTED' => 'Running '.$provider.(isset($d['alias']) ? ' on '.$d['alias'] : ''),
            'PROVIDER_COMPLETED' => ucfirst($provider).' finished',
            'PROVIDER_FAILED' => ucfirst($provider).' failed',
            'CORRELATION_ADDED' => 'Cross-check '.self::subject((string) ($d['key'] ?? '')).': '.match ($d['relation'] ?? '') {
                'agreement' => 'sources agree', 'conflict' => 'sources DISAGREE', 'complement' => 'sources complement each other', default => (string) ($d['relation'] ?? ''),
            },
            'FINDING_ADDED' => 'Recorded a finding',
            'RUN_ENDED' => 'Investigation finished',
            default => null,
        };
    }

    public static function provider(string $id): string
    {
        return match ($id) {
            'native:synthetic' => 'the network scan (recorded lab scan)',
            'native:nmap' => 'nmap',
            'native:logfile' => 'the log reader',
            'native:cve_matcher' => 'the offline CVE matcher',
            'mcp:asset-inventory' => 'the asset inventory (MCP server)',
            default => $id,
        };
    }

    /** "service|lab-web-01|8080|tcp" -> "lab-web-01 port 8080". */
    public static function subject(string $key): string
    {
        $parts = explode('|', $key);
        if (($parts[0] ?? '') === 'service' && count($parts) >= 3) {
            return $parts[1].' port '.$parts[2];
        }

        return str_replace('|', ' ', $key);
    }
}
