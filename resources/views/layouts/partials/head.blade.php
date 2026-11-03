<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="csrf-token" content="{{ csrf_token() }}">
<title>{{ isset($title) && trim($title) !== '' ? trim($title).' — ' : '' }}AEGIS</title>
<script>
    // Apply the saved theme before first paint (same key as the original dashboard). The design is
    // dark-first, so a first visit gets dark unless the person chose light.
    (function () {
        var choice = 'dark';
        try { choice = localStorage.getItem('aegis-theme') || 'dark'; } catch (e) {}
        var dark = choice !== 'light' && (choice !== 'system' || window.matchMedia('(prefers-color-scheme: dark)').matches);
        document.documentElement.dataset.theme = dark ? 'dark' : 'light';
        document.documentElement.classList.add('js');
    })();
</script>
@vite(['resources/css/app.css', 'resources/css/aegis.css', 'resources/js/app.js'])
