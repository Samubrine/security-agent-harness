@props(['value'])

<label {{ $attributes->merge(['class' => 'small-label field-label']) }}>
    {{ $value ?? $slot }}
</label>
