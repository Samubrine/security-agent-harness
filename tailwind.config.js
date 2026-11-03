import forms from '@tailwindcss/forms';

/**
 * Tailwind only supplies utility classes for the Breeze auth/profile views. The look itself
 * comes from resources/css/aegis.css (the AEGIS dashboard design system), so Tailwind's reset
 * and global form styles are off to keep them from overriding it.
 *
 * @type {import('tailwindcss').Config}
 */
export default {
    darkMode: ['selector', '[data-theme="dark"]'],
    corePlugins: { preflight: false },
    content: [
        './vendor/laravel/framework/src/Illuminate/Pagination/resources/views/*.blade.php',
        './storage/framework/views/*.php',
        './resources/views/**/*.blade.php',
    ],
    plugins: [forms({ strategy: 'class' })],
};
