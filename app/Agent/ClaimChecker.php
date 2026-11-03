<?php

namespace App\Agent;

use App\Agent\Harness\RunArchive;
use App\Models\EvidenceArtifact;
use Illuminate\Support\Collection;

/**
 * Checks the hard facts in an answer against the evidence artifacts of the conversation.
 *
 * The harness already refuses findings without evidence; this does the same for the chat answer,
 * deterministically and after the model has finished. It checks the facts a reader would act on
 * and that can be checked mechanically: CVE ids, CVSS scores attributed to a CVE, run ids, and
 * "exploited in the wild" claims. It does not judge prose.
 */
class ClaimChecker
{
    private const CVE = '/\bCVE-\d{4}-\d{4,7}\b/i';

    private const RUN = '/\brun-\d{8}T\d{6}-[a-z0-9]{4}\b/';

    public function __construct(private readonly RunArchive $archive) {}

    /**
     * @param  Collection<int, EvidenceArtifact>  $artifacts  everything tools returned in this conversation
     * @return array{checked: int, supported: int, issues: list<array{claim: string, problem: string}>, artifacts: int}
     */
    public function check(string $answer, Collection $artifacts): array
    {
        $text = $artifacts->map(fn (EvidenceArtifact $a) => EvidenceArtifact::canonicalJson($a->content))->implode("\n");
        preg_match_all(self::CVE, $text, $m);
        $knownCves = array_flip(array_map('strtoupper', $m[0]));
        preg_match_all(self::RUN, $text, $m);
        $knownRuns = array_flip($m[0]);
        [$scores, $exploited] = $this->facts($artifacts);

        $checked = 0;
        $issues = [];
        $seen = [];

        preg_match_all(self::CVE, $answer, $m);
        foreach (array_unique(array_map('strtoupper', $m[0])) as $cve) {
            $checked++;
            if (! isset($knownCves[$cve])) {
                $issues[] = ['claim' => $cve, 'problem' => 'does not appear in any tool result in this conversation'];
            }
        }

        foreach ($this->sentences($answer) as $sentence) {
            preg_match_all(self::CVE, $sentence, $cm);
            $cves = array_values(array_unique(array_map('strtoupper', $cm[0])));
            if (count($cves) !== 1) {
                continue; // a score next to several CVE ids cannot be attributed reliably
            }
            $cve = $cves[0];
            if (preg_match('/(?:CVSS|score|skor)\D{0,12}(\d{1,2}(?:[.,]\d)?)|(\d{1,2}(?:[.,]\d)?)\s*(?:\/|out of|dari)\s*10\b/i', $sentence, $sm)) {
                $value = (float) str_replace(',', '.', $sm[1] !== '' ? $sm[1] : $sm[2]);
                $key = $cve.'@'.$value;
                if (! isset($seen[$key])) {
                    $seen[$key] = true;
                    $checked++;
                    if (! isset($scores[$cve])) {
                        $issues[] = ['claim' => "{$cve} CVSS {$value}", 'problem' => 'no tool result gives a CVSS score for this CVE'];
                    } elseif (abs($scores[$cve] - $value) > 0.05) {
                        $issues[] = ['claim' => "{$cve} CVSS {$value}", 'problem' => 'the evidence says '.$scores[$cve]];
                    }
                }
            }
            if (preg_match('/exploited in the wild|actively exploited|known exploited|\bKEV\b|dieksploitasi/i', $sentence)
                && ! preg_match('/\b(not|no|never|tidak|belum|bukan)\b/i', $sentence)) {
                $checked++;
                if (($exploited[$cve] ?? null) === false) {
                    $issues[] = ['claim' => "{$cve} is exploited in the wild", 'problem' => 'the NVD lookup says it is not in CISA\'s known-exploited list'];
                } elseif (! array_key_exists($cve, $exploited)) {
                    $issues[] = ['claim' => "{$cve} is exploited in the wild", 'problem' => 'this CVE was not looked up, so the claim is unchecked'];
                }
            }
        }

        preg_match_all(self::RUN, $answer, $m);
        foreach (array_unique($m[0]) as $run) {
            $checked++;
            if (! isset($knownRuns[$run]) && ! $this->archive->exists($run)) {
                $issues[] = ['claim' => $run, 'problem' => 'no investigation with this id exists'];
            }
        }

        return ['checked' => $checked, 'supported' => $checked - count($issues), 'issues' => $issues, 'artifacts' => $artifacts->count()];
    }

    /**
     * CVSS scores and exploited flags, from NVD lookups and from harness findings' evidence text.
     *
     * @param  Collection<int, EvidenceArtifact>  $artifacts
     * @return array{0: array<string, float>, 1: array<string, bool>}
     */
    private function facts(Collection $artifacts): array
    {
        $scores = [];
        $exploited = [];
        foreach ($artifacts as $artifact) {
            $c = $artifact->content;
            $records = isset($c['results']) && is_array($c['results']) ? $c['results'] : [$c];
            foreach ($records as $r) {
                if (is_array($r) && isset($r['id']) && is_string($r['id']) && isset($r['cvss_score'])) {
                    $scores[strtoupper($r['id'])] = (float) $r['cvss_score'];
                    if (array_key_exists('known_exploited', $r)) {
                        $exploited[strtoupper($r['id'])] = (bool) $r['known_exploited'];
                    }
                }
            }
            // Harness evidence statements: "CVE-2020-1938 applies to tomcat 9.0.30 (CVSS 9.8)".
            preg_match_all('/(CVE-\d{4}-\d{4,7})[^()"]{0,160}\(CVSS (\d{1,2}(?:\.\d)?)\)/i', EvidenceArtifact::canonicalJson($c), $m, PREG_SET_ORDER);
            foreach ($m as $hit) {
                $scores[strtoupper($hit[1])] ??= (float) $hit[2];
            }
        }

        return [$scores, $exploited];
    }

    /** @return list<string> */
    private function sentences(string $text): array
    {
        $parts = preg_split('/(?<=[.!?])\s+|\n+/', $text) ?: [];

        return array_values(array_filter(array_map('trim', $parts)));
    }
}
