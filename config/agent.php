<?php

/*
|--------------------------------------------------------------------------
| Agentic chat configuration
|--------------------------------------------------------------------------
|
| The chat agent is an LLM in a loop with tools. The LLM decides which tool to call; Laravel
| executes the call, records it as a ToolExecutionLog, and feeds the result back until the
| model has enough to answer. Everything here can be overridden from .env.
|
*/

// Same location scripts/gen_scope_keypair.py uses: $XDG_CONFIG_HOME or ~/.config.
$home = getenv('USERPROFILE') ?: (getenv('HOME') ?: '');
$configHome = getenv('XDG_CONFIG_HOME') ?: $home.DIRECTORY_SEPARATOR.'.config';
$scopeDir = $configHome.DIRECTORY_SEPARATOR.'security-agent-harness';

$defaultPython = 'python';
foreach (['.venv/Scripts/python.exe', '.venv/bin/python'] as $candidate) {
    if (is_file(base_path($candidate))) {
        $defaultPython = base_path($candidate);
        break;
    }
}

return [

    // Any OpenAI-compatible /chat/completions endpoint. Defaults to the ITS LLM gateway.
    'llm' => [
        'base_url' => rtrim(env('LLM_BASE_URL', 'https://senopati.its.ac.id/llm-gateway/v1'), '/'),
        'api_key' => env('LLM_API_KEY'),
        'model' => env('LLM_MODEL', 'qwen3:14b'),
        'temperature' => (float) env('LLM_TEMPERATURE', 0.2),
        'timeout' => (int) env('LLM_TIMEOUT', 120),
        // native: send OpenAI `tools` and read `tool_calls`.
        // json:   describe the tools in the prompt and parse <tool_call>{...}</tool_call> from text.
        // auto:   native first; fall back to json if the gateway rejects `tools`.
        'tool_mode' => env('LLM_TOOL_MODE', 'auto'),
    ],

    // Optional CA bundle (PEM) for outgoing HTTPS. Set by scripts/setup.py when PHP has none.
    'ca_bundle' => env('AGENT_CA_BUNDLE'),

    // Hard stop for the agent loop: at most this many LLM turns per user message.
    'max_steps' => (int) env('AGENT_MAX_STEPS', 6),

    // How many earlier chat messages are replayed to the model as conversation history.
    'history_messages' => (int) env('AGENT_HISTORY_MESSAGES', 12),

    // The Python investigation harness that lives in this same repository (src/harness).
    'harness' => [
        'python' => env('HARNESS_PYTHON', $defaultPython),
        'root' => env('HARNESS_ROOT', base_path()),
        'scope' => env('HARNESS_SCOPE', $scopeDir.DIRECTORY_SEPARATOR.'lab_scope.signed.json'),
        'public_key' => env('HARNESS_PUBLIC_KEY', $scopeDir.DIRECTORY_SEPARATOR.'scope_ed25519_public.pem'),
        'runs_dir' => env('HARNESS_RUNS_DIR', storage_path('app/harness-runs')),
        'timeout' => (int) env('HARNESS_TIMEOUT', 180),
        // scripted: the harness's deterministic planner (fast, always works offline).
        // llm:      the harness plans with the same LLM as the chat, and falls back to the
        //           scripted planner if the model cannot produce a valid plan.
        'planner' => env('HARNESS_PLANNER', 'llm'),
        // Ask the operator before MEDIUM-risk harness calls as well as HIGH-risk ones. The shipped
        // MCP server (asset inventory) is MEDIUM, so with this on it never runs without an OK.
        'strict' => (bool) env('HARNESS_STRICT', true),
        // MCP servers the harness starts and registers as providers (see mcp_servers/).
        'mcp_config' => env('HARNESS_MCP_CONFIG', base_path('config/mcp_servers.json')),
        'skills_dir' => env('HARNESS_SKILLS_DIR', base_path('src/harness/skills')),
    ],

    // Public vulnerability information: NIST National Vulnerability Database, CVE API 2.0.
    'nvd' => [
        'base_url' => env('NVD_BASE_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0'),
        'api_key' => env('NVD_API_KEY'),
        'timeout' => (int) env('NVD_TIMEOUT', 20),
    ],

];
