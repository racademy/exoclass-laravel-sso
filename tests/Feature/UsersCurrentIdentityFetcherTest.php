<?php

declare(strict_types=1);

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Exceptions\MalformedResponseException;
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

it('refuses an UNSCOPED answer to a scoped question instead of reading the union as roles held there', function () {
    // ExoClass answers 200-with-everything when it cannot resolve an
    // X-Provider-Key (UserController::currentUser throws away the result of
    // resolveIdFromExternalKey and falls through to the unfiltered branch), so
    // a stale or re-keyed provider would otherwise hand a resolver the user's
    // roles at EVERY employer as roles at this one.
    Http::fake([
        '*' => Http::sequence()
            ->push(ssoFixture('users-current-unscoped'))
            ->push(ssoFixture('users-current-unscoped')),
    ]);

    $identity = fetcher()->fetch(credential());

    expect(fn () => $identity->rolesFor('decafbad-7777-8888-9999-aaaabbbbcccc'))
        ->toThrow(MalformedResponseException::class);
});

it('refuses an answer scoped to a DIFFERENT provider than the one asked about', function () {
    Http::fake([
        '*' => Http::sequence()
            ->push(ssoFixture('users-current-unscoped'))
            // Scoped, valid, and about Robotikos akademija — but we asked
            // about Brain Club.
            ->push(ssoFixture('users-current-scoped')),
    ]);

    $identity = fetcher()->fetch(credential());

    expect(fn () => $identity->hasRoleAt('decafbad-7777-8888-9999-aaaabbbbcccc', 'provider'))
        ->toThrow(MalformedResponseException::class);
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
