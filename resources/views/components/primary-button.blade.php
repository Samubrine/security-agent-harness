<button {{ $attributes->merge(['type' => 'submit', 'class' => 'button primary']) }}>
    {{ $slot }}
</button>
