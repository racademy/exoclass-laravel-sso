<?php

declare(strict_types=1);

use ExoClass\Sso\Exceptions\MalformedResponseException;
use ExoClass\Sso\Identity\Employer;
use ExoClass\Sso\Identity\ExoClassIdentity;

/**
 * These are CONTRACT tests: they pin the shape of ExoClass's answers against
 * committed fixtures, so an upstream change breaks the build here instead of
 * silently locking every user out of a subsystem at 9am.
 */
it('parses the unscoped users/current answer', function () {
    $identity = ExoClassIdentity::fromArray(ssoFixture('users-current-unscoped'));

    expect($identity->user->id)->toBe(48211)
        ->and($identity->user->externalKey)->toBe('a1b2c3d4-0000-4444-8888-99990000aaaa')
        ->and($identity->user->email)->toBe('mentorius@robotikosakademija.lt')
        ->and($identity->user->firstName)->toBe('Mentorius')
        ->and($identity->user->lastName)->toBe('Pavyzdys')
        ->and($identity->user->language)->toBe('lt')
        ->and($identity->user->fullName())->toBe('Mentorius Pavyzdys');
});

it('lists every employer of an unscoped answer', function () {
    $identity = ExoClassIdentity::fromArray(ssoFixture('users-current-unscoped'));

    expect($identity->employers)->toHaveCount(2)
        ->and($identity->employers[0])->toBeInstanceOf(Employer::class)
        ->and($identity->employers[0]->id)->toBe(1042)
        ->and($identity->employers[0]->externalKey)->toBe('c0ffee00-1111-2222-3333-444455556666')
        ->and($identity->employers[0]->name)->toBe('Robotikos akademija')
        ->and($identity->employers[1]->id)->toBe(2077)
        ->and($identity->employerByExternalKey('decafbad-7777-8888-9999-aaaabbbbcccc')?->name)->toBe('Brain Club')
        ->and($identity->employerByExternalKey('no-such-key'))->toBeNull();
});

it('reads role NAMES out of the role objects, unattributed on an unscoped answer', function () {
    $identity = ExoClassIdentity::fromArray(ssoFixture('users-current-unscoped'));

    // The union across both employers: this is exactly why a scoped call exists.
    expect($identity->roles)->toBe(['provider', 'teacher']);
});

it('parses the scoped users/current answer down to the one provider', function () {
    $identity = ExoClassIdentity::fromArray(ssoFixture('users-current-scoped'));

    expect($identity->user->id)->toBe(48211)
        ->and($identity->roles)->toBe(['provider'])
        ->and($identity->employers)->toHaveCount(1)
        ->and($identity->employers[0]->externalKey)->toBe('c0ffee00-1111-2222-3333-444455556666');
});

it('accepts the data envelope as well as a bare payload', function () {
    $bare = ssoFixture('users-current-unscoped');
    $wrapped = ExoClassIdentity::fromArray(['data' => $bare]);
    $nested = ExoClassIdentity::fromArray(['data' => ['user' => $bare]]);

    expect($wrapped->user->email)->toBe('mentorius@robotikosakademija.lt')
        ->and($wrapped->employers)->toHaveCount(2)
        ->and($nested->user->email)->toBe('mentorius@robotikosakademija.lt')
        ->and($nested->employers)->toHaveCount(2);
});

it('finds roles and employers beside the user object as well as inside it', function () {
    $bare = ssoFixture('users-current-unscoped');
    $roles = $bare['roles'];
    $employers = $bare['employers'];
    unset($bare['roles'], $bare['employers']);

    $identity = ExoClassIdentity::fromArray([
        'user' => $bare,
        'roles' => $roles,
        'employers' => $employers,
    ]);

    expect($identity->roles)->toBe(['provider', 'teacher'])
        ->and($identity->employers)->toHaveCount(2);
});

it('accepts plain-string roles as well as role objects', function () {
    expect(ExoClassIdentity::parseRoleNames(['provider', 'administrator']))->toBe(['provider', 'administrator'])
        ->and(ExoClassIdentity::parseRoleNames([['id' => 3, 'name' => 'provider'], ['id' => 3, 'name' => 'provider']]))->toBe(['provider'])
        ->and(ExoClassIdentity::parseRoleNames(null))->toBe([])
        ->and(ExoClassIdentity::parseRoleNames([['id' => 9]]))->toBe([]);
});

it('refuses a payload with no identifiable user rather than inventing one', function (array $payload) {
    ExoClassIdentity::fromArray($payload, url: 'https://api.exoclass.test/api/v1/lt/users/current');
})->with([
    'empty' => [[]],
    'no user at all' => [['message' => 'Unauthenticated.']],
    'no id' => [['email' => 'someone@example.com']],
    'no email' => [['id' => 48211]],
    'blank email' => [['id' => 48211, 'email' => '  ']],
])->throws(MalformedResponseException::class);

it('tolerates numeric ids arriving as strings', function () {
    $identity = ExoClassIdentity::fromArray([
        'id' => '48211',
        'email' => 'mentorius@robotikosakademija.lt',
        'employers' => [['id' => '1042', 'external_key' => 'k', 'name' => 'RA']],
    ]);

    expect($identity->user->id)->toBe(48211)
        ->and($identity->employers[0]->id)->toBe(1042);
});

it('asks the fetcher once per provider key and remembers the answer', function () {
    $calls = [];

    $identity = ExoClassIdentity::fromArray(
        ssoFixture('users-current-unscoped'),
        function (string $providerKey) use (&$calls): array {
            $calls[] = $providerKey;

            return $providerKey === 'c0ffee00-1111-2222-3333-444455556666' ? ['provider'] : ['teacher'];
        },
    );

    expect($identity->rolesFor('c0ffee00-1111-2222-3333-444455556666'))->toBe(['provider'])
        ->and($identity->rolesFor('c0ffee00-1111-2222-3333-444455556666'))->toBe(['provider'])
        ->and($identity->rolesFor('decafbad-7777-8888-9999-aaaabbbbcccc'))->toBe(['teacher'])
        ->and($calls)->toBe([
            'c0ffee00-1111-2222-3333-444455556666',
            'decafbad-7777-8888-9999-aaaabbbbcccc',
        ]);
});

it('answers hasRoleAt case-insensitively for any of the accepted roles', function () {
    $identity = ExoClassIdentity::fromArray(
        ssoFixture('users-current-unscoped'),
        fn (string $providerKey): array => ['Administrator'],
    );

    expect($identity->hasRoleAt('any-key', 'provider', 'administrator'))->toBeTrue()
        ->and($identity->hasRoleAt('any-key', 'provider'))->toBeFalse();
});

it('refuses to guess roles when no loader is bound', function () {
    ExoClassIdentity::fromArray(ssoFixture('users-current-unscoped'))->rolesFor('any-key');
})->throws(LogicException::class, 'no roles loader bound');
