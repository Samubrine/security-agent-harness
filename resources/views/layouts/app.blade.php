@php
    $onWorkspace = request()->routeIs('investigations.index');
    $workspaceViews = [
        'overview' => 'Overview',
        'findings' => 'Findings',
        'evidence' => 'Evidence',
        'trace' => 'Trace',
        'activity' => 'Activity',
        'report' => 'Report',
    ];
    $user = Auth::user();
    $displayName = trim(preg_replace('/\s*\(.*\)/', '', $user->name));
    $initials = collect(preg_split('/\s+/', $displayName))->filter()->take(2)->map(fn ($p) => mb_strtoupper(mb_substr($p, 0, 1)))->implode('');
    $links = [
        ['label' => 'Agent', 'href' => route('chat.index'), 'active' => request()->routeIs('chat.*')],
        ['label' => 'Investigations', 'href' => route('investigations.index'), 'active' => $onWorkspace],
    ];
@endphp
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    @include('layouts.partials.head', ['title' => $title ?? ''])
    {{ $head ?? '' }}
</head>
<body class="has-nav">
@include('layouts.partials.icons')
<a class="skip-link" href="#main">Skip to content</a>

<div class="statusbar" role="status">
    <div class="statusbar-inner">
        <span class="statusbar-scope"><span>{{ $environment ?? 'SIGNED LAB SCOPE' }}</span></span>
        <span class="statusbar-crumb">{{ $section ?? 'Workspace' }} / <b id="breadcrumb">{{ $breadcrumb ?? 'Overview' }}</b></span>
        <span class="statusbar-model" title="Language model used by the agent">MODEL {{ config('agent.llm.model') }}</span>
        <span class="statusbar-agent"><i class="agent-dot" aria-hidden="true"></i><span id="agent-status">AGENT IDLE</span></span>
    </div>
</div>

<header class="topnav" x-data="{ menu: false }" @keydown.escape.window="if (menu) { menu = false; $refs.menuButton.focus() }">
    <div class="topnav-inner">
        <a class="brand" href="{{ route('chat.index') }}" aria-label="AEGIS home">
            <svg class="brand-mark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5l8 3v6.2c0 4.4-3.1 8-8 9.8-4.9-1.8-8-5.4-8-9.8V5.5z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8.5 12l2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <span>AEGIS</span>
        </a>

        <nav class="topnav-links" aria-label="Main">
            @foreach ($links as $link)
                <a class="toplink {{ $link['active'] ? 'active' : '' }}" href="{{ $link['href'] }}" @if($link['active']) aria-current="page" @endif>{{ $link['label'] }}</a>
            @endforeach
        </nav>

        <div class="topnav-actions">
            <button type="button" class="icon-btn" id="theme-toggle" aria-label="Switch to light theme" title="Switch theme">
                <svg class="icon icon-sun" aria-hidden="true"><use href="#i-sun"/></svg>
                <svg class="icon icon-moon" aria-hidden="true"><use href="#i-moon"/></svg>
            </button>
            <div class="usermenu" @click.outside="menu = false">
                <button type="button" class="user-pill" x-ref="menuButton" @click="menu = !menu" :aria-expanded="menu" aria-haspopup="menu" aria-controls="user-menu">
                    <span class="user-initials">{{ $initials ?: '?' }}</span>
                    <svg class="icon icon-chevron" :class="{ 'is-open': menu }" aria-hidden="true"><use href="#i-chevron"/></svg>
                    <span class="sr-only">Account menu for {{ $displayName }}</span>
                </button>
                <div id="user-menu" class="menu" role="menu" x-show="menu" x-cloak
                     x-transition:enter="menu-enter" x-transition:enter-start="menu-from" x-transition:enter-end="menu-to"
                     x-transition:leave="menu-leave" x-transition:leave-start="menu-to" x-transition:leave-end="menu-from">
                    <p class="menu-name">{{ $displayName }}<small>{{ $user->email }}</small></p>
                    <a role="menuitem" href="{{ route('profile.edit') }}">Profile and password</a>
                    <form method="POST" action="{{ route('logout') }}" data-pending="Logging out…">
                        @csrf
                        <button role="menuitem" type="submit">Log out</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</header>

<div class="frame">
    <main id="main" tabindex="-1">
        @isset($header)
            <div class="page-heading"><div>{{ $header }}</div></div>
        @endisset

        @if ($onWorkspace)
            {{-- Tab strip: workspace.js switches the view without reloading. --}}
            <div class="tabs-wrap">
                <nav class="tabs" aria-label="Investigation views">
                    @foreach ($workspaceViews as $key => $label)
                        <button type="button" class="nav tab {{ $key === 'overview' ? 'active' : '' }}" data-view="{{ $key }}">{{ $label }}</button>
                    @endforeach
                </nav>
            </div>
        @endif

        {{ $slot }}

        <footer class="legal"><span>AEGIS · Agentic Security Investigation System</span><span>Kelompok 6 · PBKK</span></footer>
    </main>
</div>

<div class="toasts" aria-live="polite" id="toasts">
    @if (session('status') && ! request()->routeIs('profile.*'))
        <div class="toast ok" role="status" data-autodismiss="6000"><svg class="icon" aria-hidden="true"><use href="#i-check"/></svg><span>{{ session('status') }}</span><button type="button" class="toast-close" aria-label="Dismiss"><svg class="icon" aria-hidden="true"><use href="#i-close"/></svg></button></div>
    @endif
    @if (session('error'))
        <div class="toast bad" role="alert"><svg class="icon" aria-hidden="true"><use href="#i-warn"/></svg><span>{{ session('error') }}</span><button type="button" class="toast-close" aria-label="Dismiss"><svg class="icon" aria-hidden="true"><use href="#i-close"/></svg></button></div>
    @endif
</div>
{{ $scripts ?? '' }}
</body>
</html>
