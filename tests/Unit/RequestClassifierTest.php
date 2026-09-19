<?php

declare(strict_types=1);

use ExoClass\Sso\Http\RequestClassifier;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;

function classifier(): RequestClassifier
{
    return new RequestClassifier(config());
}

/**
 * A request shaped like the browser navigation it claims to be.
 *
 * @param  array<string, string>  $headers
 */
function navigation(string $uri = '/dashboard', string $method = 'GET', array $headers = ['Accept' => 'text/html'], bool $withSession = true): Request
{
    $request = Request::create($uri, $method);

    foreach ($headers as $name => $value) {
        $request->headers->set($name, $value);
    }

    if ($withSession) {
        $request->setLaravelSession(new Store('exoclass-sso-test', new ArraySessionHandler(60)));
    }

    return $request;
}

it('probes a plain HTML navigation', function () {
    expect(classifier()->isProbeable(navigation()))->toBeTrue();
});

it('probes a bare GET that states no preference, which is what a browser address bar sends', function () {
    expect(classifier()->isProbeable(navigation('/', 'GET', ['Accept' => '*/*'])))->toBeTrue();
});

it('never probes on a verb that cannot be a navigation', function (string $method) {
    expect(classifier()->isProbeable(navigation('/dashboard', $method)))->toBeFalse();
})->with(['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

it('never probes a request that wants data rather than a page', function (array $headers) {
    expect(classifier()->isProbeable(navigation('/dashboard', 'GET', $headers)))->toBeFalse();
})->with([
    'json only' => [['Accept' => 'application/json']],
    'xhr' => [['Accept' => '*/*', 'X-Requested-With' => 'XMLHttpRequest']],
    'an image' => [['Accept' => 'image/avif,image/webp,*/*']],
]);

it('never probes the paths that are not pages', function (string $uri) {
    expect(classifier()->isProbeable(navigation($uri)))->toBeFalse();
})->with([
    'livewire' => ['/livewire/update'],
    'livewire assets' => ['/livewire/livewire.js'],
    'wire' => ['/wire/poll'],
    'health' => ['/up'],
    'health check' => ['/health'],
    'api' => ['/api/v1/messages'],
    'vite build' => ['/build/assets/app-1a2b3c.js'],
    'css' => ['/css/app.css'],
    'images' => ['/images/logo.png'],
    'storage' => ['/storage/exports/report.xlsx'],
    'favicon' => ['/favicon.ico'],
    'robots' => ['/robots.txt'],
    'a stylesheet anywhere' => ['/filament/assets/theme.css'],
    'a script anywhere' => ['/vendor/filament/app.js'],
]);

it('never probes without a session, because the throttle marker would have nowhere to live', function () {
    expect(classifier()->isProbeable(navigation(withSession: false)))->toBeFalse();
});

it('lets an operator extend the ignore list without a release', function () {
    config()->set('exoclass-sso.ignore_paths', ['internal/*']);

    expect(classifier()->isProbeable(navigation('/internal/metrics')))->toBeFalse()
        // The configured list REPLACES the defaults, so an operator who narrows
        // it knows exactly what is exempt — no invisible inherited entries.
        ->and(classifier()->isProbeable(navigation('/livewire/update')))->toBeTrue();
});
