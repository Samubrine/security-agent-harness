<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    @include('layouts.partials.head', ['title' => $title ?? ''])
</head>
<body class="guest">
@include('layouts.partials.icons')
<div class="frame auth-frame">
    <div class="auth-grid">
        <section class="auth-main">
            <a class="brand" href="/" aria-label="AEGIS home">
                <svg class="brand-mark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5l8 3v6.2c0 4.4-3.1 8-8 9.8-4.9-1.8-8-5.4-8-9.8V5.5z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8.5 12l2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                <span>AEGIS</span>
            </a>
            <div class="auth-copy enter">
                <p class="eyebrow">AGENTIC SECURITY INVESTIGATION</p>
                <h1>{{ $heading ?? 'Investigate with evidence' }}</h1>
                <p class="lead">{{ $lead ?? 'Ask in plain language. The agent runs signed, in-scope checks and answers only from what it can show.' }}</p>
            </div>
            <div class="auth-form enter" style="--i:1">
                {{ $slot }}
            </div>
            <p class="legal-line">Kelompok 6 · PBKK · Lab scope only</p>
        </section>
        <aside class="auth-art" aria-hidden="true">
            <div class="glow"></div>
            @include('partials.scope-map')
            <div class="shield-glass"><svg viewBox="0 0 24 24"><use href="#i-shield"/></svg></div>
        </aside>
    </div>
</div>
</body>
</html>
