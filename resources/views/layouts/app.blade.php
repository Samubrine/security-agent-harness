@php
    $onWorkspace = request()->routeIs('investigations.index');
    $workspaceViews = [
        'overview' => 'Overview',
        'findings' => 'Findings',
        'evidence' => 'Evidence',
        'trace' => 'Investigation trace',
        'activity' => 'Activity log',
        'report' => 'Report',
    ];
    $user = Auth::user();
    $initials = collect(preg_split('/\s+/', trim(preg_replace('/\(.*\)/', '', $user->name))))->filter()->take(2)->map(fn ($p) => mb_strtoupper(mb_substr($p, 0, 1)))->implode('');
@endphp
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    @include('layouts.partials.head', ['title' => $title ?? ''])
    {{ $head ?? '' }}
</head>
<body>
<aside class="sidebar">
    <a class="brand" href="{{ route('chat.index') }}" aria-label="AEGIS home"><span class="logo">A</span>AEGIS</a>
    <p class="brand-description">Agentic Security<br>Investigation System</p>

    <p class="nav-label">AGENT</p>
    <nav aria-label="Agent">
        <a class="nav {{ request()->routeIs('chat.*') ? 'active' : '' }}" href="{{ route('chat.index') }}">Conversations</a>
    </nav>

    <p class="nav-label">WORKSPACE</p>
    <nav aria-label="Investigation workspace">
        @foreach ($workspaceViews as $key => $label)
            @if ($onWorkspace)
                <button class="nav {{ $key === 'overview' ? 'active' : '' }}" data-view="{{ $key }}">{{ $label }}</button>
            @else
                <a class="nav" href="{{ route('investigations.index', ['view' => $key]) }}">{{ $label }}</a>
            @endif
        @endforeach
    </nav>

    <div class="sidebar-bottom">
        <label class="small-label" for="theme">APPEARANCE</label>
        <select id="theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select>
        <div class="local-indicator" title="Language model used by the agent"><i></i> {{ config('agent.llm.model') }}</div>
        <div class="profile">
            <span class="avatar">{{ $initials ?: '?' }}</span>
            <div class="profile-name">
                {{ preg_replace('/\s*\(.*\)/', '', $user->name) }}
                <small><a href="{{ route('profile.edit') }}">Profile</a> ·
                    <form method="POST" action="{{ route('logout') }}" style="display:inline">@csrf<button type="submit">Log out</button></form>
                </small>
            </div>
        </div>
    </div>
</aside>

<div class="shell">
    <header class="topbar">
        <div>{{ $section ?? 'Workspace' }} <span>/</span> <b id="breadcrumb">{{ $breadcrumb ?? 'Overview' }}</b></div>
        <span class="environment"><i></i> {{ $environment ?? 'SIGNED LAB SCOPE' }}</span>
    </header>
    <main>
        @isset($header)
            <div class="page-heading"><div>{{ $header }}</div></div>
        @endisset

        @if (session('status') && ! request()->routeIs('profile.*'))
            <div class="flash" role="status">{{ session('status') }}</div>
        @endif
        @if (session('error'))
            <div class="flash error" role="alert">{{ session('error') }}</div>
        @endif

        {{ $slot }}

        <footer><span>AEGIS · Agentic Security Investigation System</span><span>Kelompok 6 · PBKK</span></footer>
    </main>
</div>
{{ $scripts ?? '' }}
</body>
</html>
