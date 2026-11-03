<x-guest-layout>
    <x-slot name="title">Confirm your password</x-slot>
    <x-slot name="heading">Confirm your password</x-slot>
    <x-slot name="lead">This area needs your password again.</x-slot>

    <div class="hint" style="margin-bottom:16px">
        {{ __('This is a secure area of the application. Please confirm your password before continuing.') }}
    </div>

    <form method="POST" action="{{ route('password.confirm') }}" data-validate data-pending="Confirming">
        @csrf

        <!-- Password -->
        <div>
            <x-input-label for="password" :value="__('Password')" />

            <x-text-input id="password" class="block mt-1 w-full"
                            type="password"
                            name="password"
                            required autocomplete="current-password" />

            <x-input-error :messages="$errors->get('password')" class="mt-2" />
        </div>

        <div class="flex justify-end mt-4">
            <x-primary-button>
                {{ __('Confirm') }}
            </x-primary-button>
        </div>
    </form>
</x-guest-layout>
