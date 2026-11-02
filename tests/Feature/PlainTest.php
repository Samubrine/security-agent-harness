<?php

namespace Tests\Feature;

use App\Models\ToolExecutionLog;
use App\Support\Plain;
use Tests\TestCase;

class PlainTest extends TestCase
{
    public function test_severity_and_status_use_everyday_words(): void
    {
        $this->assertSame('Fix now', Plain::severity('critical')[0]);
        $this->assertSame('For your information', Plain::severity('nonsense')[0]);
        $this->assertSame('Likely, not yet confirmed', Plain::status('possible'));
    }

    public function test_finding_titles_lose_the_jargon(): void
    {
        $this->assertSame('tomcat 9.0.30 has a known security flaw (CVE-2020-1938)', Plain::findingTitle('tomcat 9.0.30 is inside the range of CVE-2020-1938'));
        $this->assertStringContainsString('tricking AI tools', Plain::findingTitle('Instruction-shaped content inside attacker-controlled data'));
        $this->assertSame('Something else', Plain::findingTitle('Something else'));
    }

    public function test_the_verdict_is_driven_by_the_worst_severity(): void
    {
        $this->assertSame('unknown', Plain::verdict([], false)['level']);
        $this->assertSame('ok', Plain::verdict([], true)['level']);
        $this->assertSame('critical', Plain::verdict(['critical' => 1, 'high' => 4], true)['level']);
        $this->assertSame('high', Plain::verdict(['high' => 2], true)['level']);
    }

    public function test_a_tool_call_is_described_as_a_sentence(): void
    {
        $log = new ToolExecutionLog(['tool_name' => 'run_investigation', 'status' => 'success', 'input_parameters' => ['skill' => 'port_scan', 'target' => 'lab-web-01'], 'output_payload' => ['findings' => [['severity' => 'critical'], ['severity' => 'low']]]]);

        $this->assertSame('Scanned lab-web-01 for open services and outdated software', Plain::toolTitle($log));
        $this->assertSame('Found 2 problems, 1 serious', Plain::toolOutcome($log));
        $this->assertNotSame('', Plain::toolReason($log));
    }
}
