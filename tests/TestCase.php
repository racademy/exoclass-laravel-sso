<?php

declare(strict_types=1);

namespace ExoClass\Sso\Tests;

use ExoClass\Sso\ExoClassSsoServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
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
        $app['config']->set('exoclass-sso.enabled', true);
        $app['config']->set('exoclass-sso.api_url', 'https://api.exoclass.test/api/v1');
        $app['config']->set('exoclass-sso.locale', 'lt');
        $app['config']->set('exoclass-sso.session_cookie_name', 'sta_exoclass_session');
        $app['config']->set('exoclass-sso.xsrf_cookie_name', 'STA-XSRF-TOKEN');
        $app['config']->set('exoclass-sso.stateful_referer', 'https://send.exoclass.test');
    }
}
