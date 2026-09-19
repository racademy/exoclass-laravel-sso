<?php

declare(strict_types=1);

/**
 * The package must stay usable by every subsystem: ExoSend is Filament,
 * ExoSign is Inertia, RA Portal is Livewire. A single stray import of any of
 * them would make the package a Filament package.
 */
arch('the package depends on no UI framework and no app model')
    ->expect('ExoClass\Sso')
    ->not->toUse([
        'Filament',
        'Livewire',
        'App\Models',
        'Illuminate\Database\Eloquent',
    ]);

arch('every file declares strict types')
    ->expect('ExoClass\Sso')
    ->toUseStrictTypes();

arch('the package never dumps')
    ->expect(['dd', 'dump', 'var_dump', 'ray'])
    ->not->toBeUsed();
