import { defineConfig } from 'vite';
import laravel from 'laravel-vite-plugin';

export default defineConfig({
    plugins: [
        laravel({
            input: ['resources/css/app.css', 'resources/css/aegis.css', 'resources/js/app.js', 'resources/js/workspace.js'],
            refresh: true,
        }),
    ],
});
