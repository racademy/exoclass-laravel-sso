<?php

declare(strict_types=1);

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Identity\UsersCurrentIdentityFetcher;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

function fetcher(): IdentityFetcher
{
    return app(IdentityFetcher::class);
}

it('is the default binding for the identity fetcher contract', function () {
    expect(fetcher())->toBeInstanceOf(UsersCurrentIdentityFetcher::class);
});

it('builds the identity from one unscoped call', function () {
    Http::fake(['*' => Http::response(ssoFixture('users-current-unscoped'))]);

    $identity = fetcher()->fetch(credential());

    expect($identity->user->email)->toBe('mentorius@robotikosakademija.lt')
        ->and($identity->employers)->toHaveCount(2);

    Http::assertSentCount(1);
    Http::assertSent(fn (Request $request): bool => $request->header('X-Provider-Key') === []);
});

it('spends one extra scoped call per provider the resolver asks about, and no more', function () {
    Http::fake([
        '*' => Http::sequence()
            ->push(ssoFixture('users-current-unscoped'))
            ->push(ssoFixture('users-current-scoped')),
    ]);

    $identity = fetcher()->fetch(credential());

    expect($identity->rolesFor('c0ffee00-1111-2222-3333-444455556666'))->toBe(['provider'])
        ->and($identity->rolesFor('c0ffee00-1111-2222-3333-444455556666'))->toBe(['provider']);

    Http::assertSentCount(2);
    Http::assertSent(fn (Request $request): bool => $request->header('X-Provider-Key') === ['c0ffee00-1111-2222-3333-444455556666']);
});

it('lets a 401 on the scoped call surface instead of quietly answering no roles', function () {
    Http::fake([
        '*' => Http::sequence()
            ->push(ssoFixture('users-current-unscoped'))
            ->push(['message' => 'Unauthenticated.'], 401),
    ]);

    $identity = fetcher()->fetch(credential());

    expect(fn () => $identity->rolesFor('c0ffee00-1111-2222-3333-444455556666'))
        ->toThrow(UnauthorizedException::class);
});

it('propagates a 401 on the first call', function () {
    Http::fake(['*' => Http::response(['message' => 'Unauthenticated.'], 401)]);

    expect(fn () => fetcher()->fetch(credential()))->toThrow(UnauthorizedException::class);
});
