<button {{ $attributes->merge(['type' => 'submit', 'class' => 'button danger']) }}>
    {{ $slot }}
</button>
