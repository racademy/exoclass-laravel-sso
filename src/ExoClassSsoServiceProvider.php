<?php

declare(strict_types=1);

namespace ExoClass\Sso;

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Http\ExoClassSessionClient;
use ExoClass\Sso\Http\Middleware\ExoClassSessionAuthenticate;
use ExoClass\Sso\Identity\UsersCurrentIdentityFetcher;
use ExoClass\Sso\Support\SsoLogger;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the package into a host app.
 *
 * Note what is NOT bound here: `IdentityResolver`. That contract is the host
 * app's half of the deal, and leaving it unbound means an app that forgets to
 * implement it fails loudly at boot rather than silently resolving nobody.
 */
final class ExoClassSsoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(self::configPath(), 'exoclass-sso');

        $this->app->singleton(SsoLogger::class, static fn (): SsoLogger => new SsoLogger);

        $this->app->singleton(ExoClassSessionClient::class, static fn ($app): ExoClassSessionClient => new ExoClassSessionClient(
            $app->make(Repository::class),
            $app->make(SsoLogger::class),
        ));

        $this->app->bind(IdentityFetcher::class, UsersCurrentIdentityFetcher::class);
    }

    public function boot(): void
    {
        // A short name for the wiring, so a Filament panel or a route group
        // reads `->middleware(['exoclass-sso'])`. The class name works too.
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('exoclass-sso', ExoClassSessionAuthenticate::class);

        if ($this->app->runningInConsole()) {
            $this->publishes([
                self::configPath() => $this->app->configPath('exoclass-sso.php'),
            ], 'exoclass-sso-config');
        }
    }

    /**
     * @return list<string>
     */
    public function provides(): array
    {
        return [ExoClassSessionClient::class, IdentityFetcher::class, SsoLogger::class];
    }

    private static function configPath(): string
    {
        return __DIR__.'/../config/exoclass-sso.php';
    }
}
