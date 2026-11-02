<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    @include('layouts.partials.head', ['title' => ''])
</head>
<body>
<div class="auth-shell">
    <div class="auth-card">
        <a class="brand" href="/"><span class="logo">A</span>AEGIS</a>
        <p class="brand-description">Agentic Security Investigation System</p>
        <div class="panel">
            {{ $slot }}
        </div>
    </div>
</div>
</body>
</html>
