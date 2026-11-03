<button {{ $attributes->merge(['type' => 'button', 'class' => 'button']) }}>
    {{ $slot }}
</button>
