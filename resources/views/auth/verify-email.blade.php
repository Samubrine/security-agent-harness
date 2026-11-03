<x-guest-layout>
    <x-slot name="title">Verify your email</x-slot>
    <x-slot name="heading">Verify your email</x-slot>
    <x-slot name="lead">Open the link we emailed you to continue.</x-slot>

    <div class="hint" style="margin-bottom:16px">
        {{ __('Thanks for signing up! Before getting started, could you verify your email address by clicking on the link we just emailed to you? If you didn\'t receive the email, we will gladly send you another.') }}
    </div>

    @if (session('status') == 'verification-link-sent')
        <div class="flash" style="margin:0 0 16px">
            {{ __('A new verification link has been sent to the email address you provided during registration.') }}
        </div>
    @endif

    <div class="mt-4 flex items-center justify-between">
        <form method="POST" action="{{ route('verification.send') }}" data-validate data-pending="Sending verification email">
            @csrf

            <div>
                <x-primary-button>
                    {{ __('Resend Verification Email') }}
                </x-primary-button>
            </div>
        </form>

        <form method="POST" action="{{ route('logout') }}">
            @csrf

            <button type="submit" class="text-button">
                {{ __('Log Out') }}
            </button>
        </form>
    </div>
</x-guest-layout>
