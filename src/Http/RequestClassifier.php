<?php

declare(strict_types=1);

namespace ExoClass\Sso\Http;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;

/**
 * Decides which requests are allowed to cost an upstream call.
 *
 * This is the whole of NFR-2 in one predicate, and it is the difference between
 * "SSO" and "a denial-of-service aimed at ExoClass from our own users": a busy
 * page fires dozens of asset, Livewire and XHR requests per navigation, and a
 * probe on each of them would multiply every page view into dozens of
 * `users/current` calls — for a signed-out visitor, forever, on a public page.
 *
 * So the answer is yes for exactly one shape of request: a GET the browser will
 * render as a page, on a path that is not an asset or a machine endpoint, with
 * a session to remember the outcome in. Everything else falls straight through
 * the middleware having asked nobody anything.
 *
 * Do not "simplify" this away.
 */
final readonly class RequestClassifier
{
    /**
     * Paths that are never a navigation. Exposed as config
     * (`exoclass-sso.ignore_paths`) rather than baked in, because every app
     * mounts its own machinery somewhere and nobody should need a package
     * release to exempt it.
     *
     * @var list<string>
     */
    public const DEFAULT_IGNORED_PATHS = [
        // Livewire / Filament round trips: same session, same cookies, many per page.
        'livewire/*',
        'wire/*',
        // Machine endpoints.
        'up',
        'health',
        'healthz',
        'api/*',
        'telescope/*',
        'horizon/*',
        // Static assets, by directory and by extension.
        'build/*',
        'js/*',
        'css/*',
        'img/*',
        'images/*',
        'fonts/*',
        'storage/*',
        'vendor/*',
        'favicon.ico',
        'favicon.*',
        'robots.txt',
        'sitemap.xml',
        '*.js',
        '*.mjs',
        '*.css',
        '*.map',
        '*.png',
        '*.jpg',
        '*.jpeg',
        '*.gif',
        '*.svg',
        '*.ico',
        '*.webp',
        '*.avif',
        '*.woff',
        '*.woff2',
        '*.ttf',
    ];

    public function __construct(private Repository $config) {}

    /**
     * May this request cost an upstream call?
     */
    public function isProbeable(Request $request): bool
    {
        if (! $request->isMethod('GET')) {
            return false;
        }

        if (! $this->wantsAPage($request) || $request->expectsJson()) {
            return false;
        }

        if ($request->is(...$this->ignoredPaths())) {
            return false;
        }

        // No session, nowhere to record that we already asked — and a probe we
        // cannot remember is a probe we would repeat on every request.
        return $request->hasSession();
    }

    /**
     * Is a PAGE what this client is after?
     *
     * `acceptsHtml()` alone is not enough, and the gap is not academic: a
     * browser fetching an image sends `Accept: image/avif,image/webp,` plus the
     * catch-all wildcard, and that trailing wildcard makes `acceptsHtml()`
     * answer true. An image served from a dynamic path — `/media/8812`, a
     * signed download, an avatar route — would then probe upstream once per
     * image on the page.
     *
     * So the question is asked of the client's FIRST preference, not of the
     * whole list: a navigation asks for HTML first, or asks for anything at all
     * (the bare wildcard, what a plain address-bar GET and curl send). A client
     * whose top preference is a concrete non-HTML type is fetching a thing,
     * not a page.
     */
    private function wantsAPage(Request $request): bool
    {
        $accepted = $request->getAcceptableContentTypes();

        if ($accepted === []) {
            return true;
        }

        return in_array(strtolower(trim($accepted[0])), [
            '*/*',
            'text/html',
            'application/xhtml+xml',
            'text/*',
        ], true);
    }

    /**
     * @return list<string>
     */
    private function ignoredPaths(): array
    {
        $configured = $this->config->get('exoclass-sso.ignore_paths');

        if (! is_array($configured) || $configured === []) {
            return self::DEFAULT_IGNORED_PATHS;
        }

        return array_values(array_filter(
            array_map(static fn (mixed $path): string => is_string($path) ? $path : '', $configured),
            static fn (string $path): bool => $path !== '',
        ));
    }
}
