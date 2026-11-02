<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="csrf-token" content="{{ csrf_token() }}">
<title>{{ isset($title) && trim($title) !== '' ? trim($title).' — ' : '' }}AEGIS</title>
<script>
    // Apply the saved theme before first paint (same key as the original dashboard).
    (function () {
        var choice = 'system';
        try { choice = localStorage.getItem('aegis-theme') || 'system'; } catch (e) {}
        var dark = choice === 'dark' || (choice !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
        document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    })();
</script>
@vite(['resources/css/app.css', 'resources/css/aegis.css', 'resources/js/app.js'])
