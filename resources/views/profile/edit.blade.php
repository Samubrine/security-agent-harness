<x-app-layout>
    <x-slot name="title">Profile</x-slot>
    <x-slot name="section">Account</x-slot>
    <x-slot name="breadcrumb">Profile</x-slot>

    <div class="page-heading">
        <div>
            <p class="eyebrow">Account</p>
            <h1>Profile</h1>
            <p class="subtitle">Your name, email address and password.</p>
        </div>
    </div>

    <div class="profile-stack">
        <section class="panel">
            @include('profile.partials.update-profile-information-form')
        </section>
        <section class="panel">
            @include('profile.partials.update-password-form')
        </section>
        <section class="panel">
            @include('profile.partials.delete-user-form')
        </section>
    </div>
</x-app-layout>
