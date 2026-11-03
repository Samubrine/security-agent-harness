@props(['status'])

@if ($status)
    <div {{ $attributes->merge(['class' => 'flash']) }} role="status">
        {{ $status }}
    </div>
@endif
