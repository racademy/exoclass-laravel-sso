<?php

declare(strict_types=1);

use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\Candidate;
use ExoClass\Sso\Resolution\ChoiceRequired;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Resolution\Resolution;
use ExoClass\Sso\Resolution\ResolutionContext;
use ExoClass\Sso\Resolution\ResolutionTrigger;
use Illuminate\Auth\GenericUser;

it('exposes exactly three outcomes, all of them Resolutions', function () {
    $user = new GenericUser(['id' => 1, 'email' => 'someone@example.com']);

    expect(new Authenticated($user))->toBeInstanceOf(Resolution::class)
        ->and(new Denied('no eligible organization'))->toBeInstanceOf(Resolution::class)
        ->and(new ChoiceRequired(new Candidate('1042', 'RA'), new Candidate('2077', 'Brain Club')))
        ->toBeInstanceOf(Resolution::class);
});

it('hands the authenticated user straight back', function () {
    $user = new GenericUser(['id' => 7, 'email' => 'someone@example.com']);

    expect((new Authenticated($user))->user)->toBe($user);
});

it('refuses a choice that is not a choice', function () {
    new ChoiceRequired(new Candidate('1042', 'RA'));
})->throws(InvalidArgumentException::class, 'at least two candidates');

it('refuses duplicate candidate keys, which would make the picker ambiguous', function () {
    new ChoiceRequired(new Candidate('1042', 'RA'), new Candidate('1042', 'RA again'));
})->throws(InvalidArgumentException::class, 'unique keys');

it('keeps the candidates in order and exposes their keys', function () {
    $choice = ChoiceRequired::fromList([
        new Candidate('1042', 'Robotikos akademija', ['organization_id' => 3]),
        new Candidate('2077', 'Brain Club'),
    ]);

    expect($choice->keys())->toBe(['1042', '2077'])
        ->and($choice->candidates[0]->toArray())->toBe([
            'key' => '1042',
            'label' => 'Robotikos akademija',
            'meta' => ['organization_id' => 3],
        ]);
});

it('refuses a candidate with no key or no label', function (string $key, string $label) {
    new Candidate($key, $label);
})->with([
    'no key' => ['', 'RA'],
    'no label' => ['1042', '  '],
])->throws(InvalidArgumentException::class);

it('insists a denial carries the reason that will be logged', function () {
    new Denied('   ');
})->throws(InvalidArgumentException::class, 'requires a reason');

it('defaults the resolution context to an auto-login attempt', function () {
    expect((new ResolutionContext)->trigger)->toBe(ResolutionTrigger::AutoLogin)
        ->and(ResolutionContext::buttonReturn('/admin/messages')->trigger)->toBe(ResolutionTrigger::ButtonReturn)
        ->and(ResolutionContext::buttonReturn('/admin/messages')->intendedUrl)->toBe('/admin/messages')
        ->and(ResolutionContext::choice()->trigger)->toBe(ResolutionTrigger::Choice)
        ->and(ResolutionContext::liveness()->trigger)->toBe(ResolutionTrigger::Liveness);
});

it('keeps the credential out of the resolver context', function () {
    $properties = array_map(
        static fn (ReflectionProperty $property): string => $property->getName(),
        (new ReflectionClass(ResolutionContext::class))->getProperties(),
    );

    expect($properties)->toBe(['trigger', 'intendedUrl', 'ipAddress', 'meta']);
});
