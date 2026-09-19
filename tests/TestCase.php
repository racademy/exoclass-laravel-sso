<?php

declare(strict_types=1);

namespace ExoClass\Sso\Tests;

use ExoClass\Sso\Actions\CompleteChoice;
use ExoClass\Sso\Actions\GlobalLogout;
use ExoClass\Sso\ExoClassSsoServiceProvider;
use ExoClass\Sso\Http\Middleware\ExoClassSessionAuthenticate;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Tests\Support\ArrayUserProvider;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        // Before the app boots, not after: the package registers its own cookie
        // exemption from the provider's boot, and flushing afterwards would
        // throw that away and hide it from every test in this suite.
        EncryptCookies::flushState();

        parent::setUp();

        ArrayUserProvider::reset();
        ExoClassSessionAuthenticate::denyUsing(null);

        Auth::provider('array', static fn (): ArrayUserProvider => new ArrayUserProvider);
    }

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [ExoClassSsoServiceProvider::class];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        $app['config']->set('exoclass-sso.enabled', true);
        $app['config']->set('exoclass-sso.api_url', 'https://api.exoclass.test/api/v1');
        $app['config']->set('exoclass-sso.locale', 'lt');
        $app['config']->set('exoclass-sso.session_cookie_name', 'sta_exoclass_session');
        $app['config']->set('exoclass-sso.xsrf_cookie_name', 'STA-XSRF-TOKEN');
        $app['config']->set('exoclass-sso.stateful_referer', 'https://send.exoclass.test');

        $app['config']->set('view.paths', [__DIR__.'/stubs']);

        // No Eloquent anywhere in this suite: the package must work for an app
        // whose users live wherever that app keeps them.
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'array']);
        $app['config']->set('auth.providers.array', ['driver' => 'array']);
    }

    /**
     * @param  Router  $router
     *
     * The host app a subsystem would wire up: the middleware sits in the `web`
     * group, after the session has started and the cookies have been decrypted.
     */
    protected function defineRoutes($router): void
    {
        $router->middleware(['web', ExoClassSessionAuthenticate::class])->group(static function (Router $router): void {
            $router->get('/dashboard', static fn (): string => 'dashboard for '.(string) (Auth::id() ?? 'a guest'))->name('dashboard');
            $router->get('/login', static fn (): string => 'the login page')->name('login');
            $router->get('/choose', static fn (): string => 'pick one of '.count(SsoSession::candidates(app('session.store'))))->name('sso.choose');
            $router->get('/up', static fn (): string => 'healthy');
            $router->get('/livewire/update', static fn (): string => 'livewire');
            $router->post('/dashboard', static fn (): string => 'saved');
            $router->post('/choose', static function (Request $request): string {
                $resolution = app(CompleteChoice::class)
                    ->handle($request, (string) $request->input('key'));

                if ($resolution instanceof Authenticated) {
                    return 'entered as '.(string) Auth::id()
                        .' heading for '.(SsoSession::pullIntendedUrl(app('session.store')) ?? 'nowhere');
                }

                return 'refused: '.($resolution instanceof Denied ? $resolution->reason : $resolution::class);
            });
            $router->get('/logout', static function (Request $request): string {
                app(GlobalLogout::class)->handle($request);
                Auth::logout();

                return 'signed out';
            });
        });
    }
}
