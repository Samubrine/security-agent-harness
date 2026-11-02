<?php

use App\Http\Controllers\ChatSessionController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return redirect()->route('chat.index');
});

Route::get('/dashboard', function () {
    return redirect()->route('chat.index');
})->middleware(['auth', 'verified'])->name('dashboard');

// Agentic AI Chat & Relational Management
Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/chat', [ChatSessionController::class, 'index'])->name('chat.index');
    Route::post('/chat', [ChatSessionController::class, 'store'])->name('chat.store');
    Route::get('/chat/{id}', [ChatSessionController::class, 'show'])->name('chat.show');
    Route::post('/chat/{id}/message', [ChatSessionController::class, 'sendMessage'])->name('chat.message');

    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');
});

require __DIR__.'/auth.php';
