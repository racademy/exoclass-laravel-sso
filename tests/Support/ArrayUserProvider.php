<?php

declare(strict_types=1);

namespace ExoClass\Sso\Tests\Support;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * A user provider with no database behind it.
 *
 * The package must never touch an app's user table, and the arch test forbids
 * it from importing Eloquent — so the test suite may not quietly depend on one
 * either. Anything this provider can do, a host app's real provider can do.
 */
final class ArrayUserProvider implements UserProvider
{
    /** @var array<int, GenericUser> */
    private static array $users = [];

    public static function add(int $id, string $email): GenericUser
    {
        return self::$users[$id] = new GenericUser([
            'id' => $id,
            'email' => $email,
            'password' => null,
            'remember_token' => null,
        ]);
    }

    public static function reset(): void
    {
        self::$users = [];
    }

    /**
     * @param  mixed  $identifier
     */
    public function retrieveById($identifier): ?Authenticatable
    {
        return is_numeric($identifier) ? (self::$users[(int) $identifier] ?? null) : null;
    }

    /**
     * @param  mixed  $identifier
     * @param  string  $token
     */
    public function retrieveByToken($identifier, #[\SensitiveParameter] $token): ?Authenticatable
    {
        return null;
    }

    /**
     * @param  string  $token
     */
    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] $token): void {}

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        return null;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validateCredentials(Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        return false;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function rehashPasswordIfRequired(Authenticatable $user, #[\SensitiveParameter] array $credentials, bool $force = false): void {}
}
