<?php

namespace App\Agent\Tools;

use App\Models\KnowledgeSource;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

/**
 * Public vulnerability information from the NIST National Vulnerability Database (CVE API 2.0).
 * Responses are cached for a day: CVE records change rarely and NVD rate-limits anonymous use.
 */
class NvdClient
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly ?string $apiKey = null,
        private readonly int $timeout = 20,
    ) {}

    public static function fromConfig(): self
    {
        $c = config('agent.nvd');

        return new self($c['base_url'], $c['api_key'], $c['timeout']);
    }

    public function source(): KnowledgeSource
    {
        return KnowledgeSource::firstOrCreate(
            ['name' => 'NVD CVE Database'],
            ['source_type' => 'public_vulnerability_db', 'provider' => 'NIST', 'endpoint' => $this->baseUrl],
        );
    }

    /**
     * @return array<string, mixed>|null null when NVD has no such CVE
     */
    public function cve(string $cveId): ?array
    {
        $data = $this->get(['cveId' => $cveId]);
        $item = $data['vulnerabilities'][0]['cve'] ?? null;

        return $item ? $this->summarise($item, detailed: true) : null;
    }

    /**
     * @return list<array<string, mixed>> highest CVSS score first
     */
    public function search(string $keyword, int $limit): array
    {
        $data = $this->get(['keywordSearch' => $keyword, 'resultsPerPage' => 40]);
        $items = array_map(fn ($v) => $this->summarise($v['cve'], detailed: false), $data['vulnerabilities'] ?? []);
        usort($items, fn ($a, $b) => ($b['cvss_score'] ?? 0) <=> ($a['cvss_score'] ?? 0));

        return array_slice($items, 0, $limit);
    }

    /**
     * @param  array<string, mixed>  $query
     * @return array<string, mixed>
     */
    private function get(array $query): array
    {
        $key = 'nvd:'.md5(json_encode($query));

        return Cache::remember($key, now()->addDay(), function () use ($query) {
            try {
                $response = Http::timeout($this->timeout)
                    ->acceptJson()
                    ->when($this->apiKey, fn ($http) => $http->withHeaders(['apiKey' => $this->apiKey]))
                    ->get($this->baseUrl, $query);
            } catch (ConnectionException $e) {
                throw new ToolException('Could not reach the NVD API: '.$e->getMessage(), 0, $e);
            }
            if ($response->status() === 403 || $response->status() === 429) {
                throw new ToolException('NVD rate limit reached; try again in about 30 seconds.');
            }
            if ($response->status() === 404) {
                return ['vulnerabilities' => []];
            }
            if ($response->failed()) {
                throw new ToolException('NVD API returned HTTP '.$response->status().'.');
            }

            return $response->json() ?? [];
        });
    }

    /**
     * @param  array<string, mixed>  $cve
     * @return array<string, mixed>
     */
    private function summarise(array $cve, bool $detailed): array
    {
        $description = collect($cve['descriptions'] ?? [])->firstWhere('lang', 'en')['value'] ?? null;
        $metric = null;
        foreach (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $version) {
            if (! empty($cve['metrics'][$version])) {
                $metric = collect($cve['metrics'][$version])->firstWhere('type', 'Primary') ?? $cve['metrics'][$version][0];
                $metric['version'] = $version;
                break;
            }
        }
        $cvss = $metric['cvssData'] ?? [];

        $out = [
            'id' => $cve['id'] ?? null,
            'published' => isset($cve['published']) ? substr($cve['published'], 0, 10) : null,
            'cvss_score' => $cvss['baseScore'] ?? null,
            'severity' => $cvss['baseSeverity'] ?? ($metric['baseSeverity'] ?? null),
            'description' => $description ? Str::limit($description, $detailed ? 900 : 260) : null,
            // CISA's Known Exploited Vulnerabilities catalog: attackers are using this in the wild.
            'known_exploited' => isset($cve['cisaExploitAdd']),
        ];

        if ($detailed) {
            $out += [
                'cvss_version' => $metric['version'] ?? null,
                'cvss_vector' => $cvss['vectorString'] ?? null,
                'status' => $cve['vulnStatus'] ?? null,
                'weaknesses' => collect($cve['weaknesses'] ?? [])
                    ->flatMap(fn ($w) => collect($w['description'] ?? [])->pluck('value'))
                    ->unique()->values()->all(),
                'cisa_required_action' => $cve['cisaRequiredAction'] ?? null,
                'references' => collect($cve['references'] ?? [])
                    ->sortByDesc(fn ($r) => count(array_intersect($r['tags'] ?? [], ['Patch', 'Vendor Advisory', 'Mitigation'])))
                    ->take(5)->pluck('url')->values()->all(),
                'nvd_url' => 'https://nvd.nist.gov/vuln/detail/'.($cve['id'] ?? ''),
            ];
        }

        return $out;
    }
}
