<?php

declare(strict_types=1);

namespace ExoClass\Sso\Http\Middleware;

use Closure;
use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Contracts\IdentityResolver;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Http\CredentialReader;
use ExoClass\Sso\Http\RequestClassifier;
use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Identity\ExoClassIdentity;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\ChoiceRequired;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Resolution\Resolution;
use ExoClass\Sso\Resolution\ResolutionContext;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Session\SuppressionCookie;
use ExoClass\Sso\Support\SsoLogger;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Throwable;

/**
 * Signs a visitor in from the ExoClass session they already have, and notices
 * when that session ends.
 *
 * The whole policy is one table, and every row of it has a test:
 *
 * | Situation                                    | What happens                              |
 * |----------------------------------------------|-------------------------------------------|
 * | flag off, or not a navigation                 | through, nothing asked                    |
 * | guest, no ExoClass cookie                     | through, nothing asked                    |
 * | guest, suppression cookie from a logout       | through, nothing asked (H-10)             |
 * | guest, a probe already failed this window     | through, nothing asked (NFR-2)            |
 * | guest, upstream 401                           | mark the probe, through                   |
 * | guest, upstream unreachable or unparseable    | warn, through — the login page must render |
 * | guest, resolver throws                        | log, through — never take the page down   |
 * | guest, Authenticated                          | sign in, continue where they were going   |
 * | guest, ChoiceRequired                         | stash candidates, redirect to the picker  |
 * | guest, Denied                                 | 403, cookie left intact, mark the probe   |
 * | signed in with a password                     | nothing, ever                             |
 * | SSO session, cookie unchanged and fresh       | nothing, no call                          |
 * | SSO session, cookie changed                   | re-validate now                           |
 * | SSO session, liveness window closed           | re-validate                               |
 * | re-validation: 401 or cookie gone             | local sign-out, redirect                  |
 * | re-validation: somebody else signed in there  | re-resolve; sign in as them, or sign out  |
 * | re-validation: upstream unreachable           | keep the session, back off                |
 *
 * Two rules explain most of it. A 401 is the only upstream answer that is a
 * VERDICT: everything else means "we could not ask", and must leave both the
 * login page and any existing session exactly as they were. And an upstream
 * call is expensive enough to deserve a reason: see {@see RequestClassifier}
 * and the two TTLs.
 *
 * Register it AFTER the session has started and cookies have been decrypted,
 * and BEFORE the app's auth guard redirects a guest — for Filament that is the
 * panel's `middleware()`, not `authMiddleware()`, or `/admin/login` itself
 * never gets the chance to sign anybody in.
 */
final class ExoClassSessionAuthenticate
{
    /**
     * Lets the host app render its own denial (a branded page, a Filament
     * notification, a redirect with an explanation) instead of a 403.
     *
     * @var (Closure(Request, Denied): Response)|null
     */
    private static ?Closure $denyUsing = null;

    private const DENIED_MESSAGE = 'Your ExoClass account has no access to this application.';

    public function __construct(
        private readonly Container $container,
        private readonly Repository $config,
        private readonly SsoLogger $logger,
        private readonly CredentialReader $credentials,
        private readonly RequestClassifier $classifier,
    ) {}

    /**
     * @param  (Closure(Request, Denied): Response)|null  $callback
     */
    public static function denyUsing(?Closure $callback): void
    {
        self::$denyUsing = $callback;
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->enabled() || ! $this->classifier->isProbeable($request)) {
            return $next($request);
        }

        if (Auth::check()) {
            return $this->revalidate($request) ?? $next($request);
        }

        return $this->attempt($request, $next);
    }

    /**
     * The guest path: is this visitor signed into ExoClass, and if so, who are
     * they here?
     *
     * @param  Closure(Request): Response  $next
     */
    private function attempt(Request $request, Closure $next): Response
    {
        $session = $request->session();

        if (SuppressionCookie::presentOn($request)) {
            return $next($request);
        }

        if (SsoSession::isThrottled($session, $this->ttl('probe_ttl', 120))) {
            return $next($request);
        }

        $credential = $this->credentials->from($request);

        if ($credential === null) {
            return $next($request);
        }

        try {
            $identity = $this->fetcher()->fetch($credential);
        } catch (UnauthorizedException) {
            // The ordinary answer for a visitor who simply is not signed into
            // ExoClass. Not an incident, not logged, and not asked again for a
            // while.
            SsoSession::markProbed($session);

            return $next($request);
        } catch (Throwable $exception) {
            // Unreachable, 5xx, or a body we cannot trust. We did not learn
            // that this visitor is a guest — only that we could not find out —
            // so the login page renders and they can use a password.
            //
            // The probe is marked anyway: an upstream in trouble is exactly the
            // one that must not be asked again on the visitor's next click.
            SsoSession::markProbed($session);

            $this->logger->warning('ExoClass SSO probe got no verdict; the visitor stays a guest.', [
                'exception' => $exception::class,
                'reason' => $exception->getMessage(),
            ], $credential->redactable());

            return $next($request);
        }

        $resolution = $this->resolve(
            $identity,
            ResolutionContext::autoLogin($request->fullUrl(), $request->ip()),
            $credential,
        );

        if ($resolution === null) {
            SsoSession::markProbed($session);

            return $next($request);
        }

        return match (true) {
            $resolution instanceof Authenticated => $this->signIn($request, $next, $resolution, $identity, $credential),
            $resolution instanceof ChoiceRequired => $this->offerChoice($request, $next, $resolution),
            $resolution instanceof Denied => $this->refuse($request, $resolution, $identity, $credential),
            default => $this->unknownResolution($request, $next, $resolution),
        };
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    private function signIn(
        Request $request,
        Closure $next,
        Authenticated $resolution,
        ExoClassIdentity $identity,
        SessionCredential $credential,
    ): Response {
        SsoSession::establish($request, $resolution->user, $credential, $identity);

        $this->logger->info('ExoClass SSO signed a visitor in.', [
            'exoclass_user_id' => $identity->user->id,
            'email' => $identity->user->email,
            'trigger' => ResolutionContext::autoLogin()->trigger->value,
        ], $credential->redactable());

        // A guarded route may have bounced this visitor to the login page and
        // left the URL they wanted behind; take them there rather than to the
        // login page they no longer need.
        $intended = $request->session()->pull('url.intended');

        return is_string($intended) && $intended !== ''
            ? redirect()->to($intended)
            : $next($request);
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    private function offerChoice(Request $request, Closure $next, ChoiceRequired $resolution): Response
    {
        $session = $request->session();
        $url = $this->choiceUrl();

        if ($url === null) {
            // The app can offer a choice but has nowhere to offer it. Refusing
            // would be worse than falling through to the password form, so log
            // loudly and carry on.
            $this->logger->error(
                'ExoClass SSO has candidates to offer but exoclass-sso.choice_route is not set; falling through.',
                ['candidates' => $resolution->keys()],
            );

            return $next($request);
        }

        // Do not redirect the picker to itself: the picker is a guest page, so
        // the middleware runs on it too and would answer ChoiceRequired again.
        if ($this->isAt($request, $url)) {
            SsoSession::putChoice($session, $resolution);

            return $next($request);
        }

        $intended = $request->session()->get('url.intended');
        $intended = is_string($intended) && $intended !== '' ? $intended : $request->fullUrl();

        SsoSession::putChoice($session, $resolution, $intended);

        return redirect()->to($url);
    }

    private function refuse(
        Request $request,
        Denied $resolution,
        ExoClassIdentity $identity,
        SessionCredential $credential,
    ): Response {
        SsoSession::markProbed($request->session());

        $this->logger->warning('ExoClass SSO refused a visitor.', [
            'exoclass_user_id' => $identity->user->id,
            'email' => $identity->user->email,
            'reason' => $resolution->reason,
        ], $credential->redactable());

        if (self::$denyUsing !== null) {
            return (self::$denyUsing)($request, $resolution);
        }

        $view = $this->config->get('exoclass-sso.denied_view');

        if (is_string($view) && trim($view) !== '') {
            return response()->view($view, ['reason' => $resolution->reason], 403);
        }

        // Let the host app render its own 403 page. Note what is NOT here: the
        // ExoClass cookie is untouched. The visitor is legitimately signed into
        // ExoClass and the sibling apps under `.exoclass.com` still need it.
        throw new AccessDeniedHttpException(self::DENIED_MESSAGE);
    }

    /**
     * An already-authenticated visitor: is the ExoClass session behind this one
     * still alive, and still theirs?
     */
    private function revalidate(Request $request): ?Response
    {
        $session = $request->session();

        // A password session is the app's own. We never established it and we
        // never call upstream about it.
        if (! SsoSession::isSso($session)) {
            return null;
        }

        $credential = $this->credentials->from($request);

        if ($credential === null) {
            // The shared cookie is gone, so the ExoClass session ended. A free
            // local verdict: no HTTP call, no throttle, effective immediately.
            return $this->tearDown($request, markProbed: true);
        }

        $unchanged = SsoSession::fingerprintMatches($session, $credential);

        // The hybrid trigger. A changed cookie value is the FAST signal —
        // ExoClass rotates the shared cookie on its own logout and on an
        // account switch, and we catch that on the next navigation instead of
        // waiting out the TTL. The TTL is the BACKSTOP for the opposite case: a
        // server-side ExoClass logout while the visitor only browses here, so
        // the browser is never handed a new cookie and the value never changes.
        if ($unchanged && SsoSession::isFresh($session, $this->ttl('liveness_ttl', 600))) {
            return null;
        }

        // A recent attempt got us nowhere. Without this, an outage during which
        // the cookie value happens to look changed turns EVERY navigation into
        // a failed upstream call for as long as the outage lasts — the one case
        // where the freshness check above cannot hold, because a changed
        // fingerprint deliberately overrides it.
        if (SsoSession::isThrottled($session, $this->ttl('probe_ttl', 120))) {
            return null;
        }

        try {
            $identity = $this->fetcher()->fetch($credential);
        } catch (UnauthorizedException) {
            return $this->tearDown($request, markProbed: true);
        } catch (Throwable $exception) {
            // An ExoClass blip must never sign anybody out. Back off so a long
            // outage does not turn every navigation into a failed call, and
            // keep the session exactly as it was.
            SsoSession::markChecked($session);
            SsoSession::markProbed($session);

            $this->logger->warning('ExoClass SSO liveness check failed; the session is kept.', [
                'exception' => $exception::class,
                'reason' => $exception->getMessage(),
            ], $credential->redactable());

            return null;
        }

        if (SsoSession::exoClassUserId($session) === $identity->user->id) {
            // Same person. Remember the cookie we just validated so a benign
            // rotation does not look "changed" on every navigation from now on.
            SsoSession::rememberFingerprint($session, $credential);
            SsoSession::markChecked($session);
            SsoSession::forgetProbe($session);

            return null;
        }

        // Somebody else is signed into ExoClass in this browser now. Whether
        // they may be here is the resolver's call, exactly as at the front door.
        $resolution = $this->resolve(
            $identity,
            ResolutionContext::liveness($request->fullUrl(), $request->ip()),
            $credential,
        );

        if ($resolution instanceof Authenticated) {
            SsoSession::establish($request, $resolution->user, $credential, $identity);

            $this->logger->info('ExoClass SSO switched to the identity now signed into ExoClass.', [
                'exoclass_user_id' => $identity->user->id,
                'email' => $identity->user->email,
            ], $credential->redactable());

            return null;
        }

        // Denied, a choice to make, or a resolver that failed: this session is
        // no longer anybody's. Drop it and let the next request start clean —
        // the picker and the 403 both live on the guest path.
        return $this->tearDown($request);
    }

    /**
     * Sign out locally and bounce, so the next request is a fresh guest hit.
     *
     * Deliberately does NOT set the suppression cookie: unlike a user-initiated
     * logout, here we WANT the next request to re-evaluate — auto-signing in as
     * the new identity, or falling through to the login page.
     */
    private function tearDown(Request $request, bool $markProbed = false): Response
    {
        Auth::logout();

        $session = $request->session();
        $session->invalidate();
        $session->regenerateToken();

        if ($markProbed) {
            // Upstream just said no. Do not ask again on the very next request.
            SsoSession::markProbed($session);
        }

        return redirect()->to($this->afterTearDownUrl($request));
    }

    /**
     * Ask the app's resolver, and treat a throwing resolver as "no answer"
     * rather than as a 500. A broken organization lookup must not be able to
     * take the login page down.
     */
    private function resolve(
        ExoClassIdentity $identity,
        ResolutionContext $context,
        SessionCredential $credential,
    ): ?Resolution {
        try {
            return $this->container->make(IdentityResolver::class)->resolve($identity, $context);
        } catch (Throwable $exception) {
            $this->logger->error('ExoClass SSO resolver failed; the visitor is treated as a guest.', [
                'exception' => $exception::class,
                'reason' => $exception->getMessage(),
                'exoclass_user_id' => $identity->user->id,
            ], $credential->redactable());

            return null;
        }
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    private function unknownResolution(Request $request, Closure $next, Resolution $resolution): Response
    {
        // The set of resolutions is closed by convention; a fourth one is a
        // package change. Inventing a fallback here would be the one way a new
        // outcome could silently mean "let them in".
        $this->logger->error('ExoClass SSO got a resolution it does not understand; treating the visitor as a guest.', [
            'resolution' => $resolution::class,
        ]);

        SsoSession::markProbed($request->session());

        return $next($request);
    }

    private function fetcher(): IdentityFetcher
    {
        // Resolved here rather than injected: this middleware runs on every
        // request, and only the rare probe path needs the fetcher and its
        // transport.
        return $this->container->make(IdentityFetcher::class);
    }

    private function enabled(): bool
    {
        return (bool) $this->config->get('exoclass-sso.enabled', false);
    }

    private function ttl(string $key, int $default): int
    {
        return (int) $this->config->get('exoclass-sso.'.$key, $default);
    }

    /**
     * The picker's URL, from a route name or a plain URL.
     */
    private function choiceUrl(): ?string
    {
        return $this->urlFromConfig('choice_route');
    }

    private function afterTearDownUrl(Request $request): string
    {
        // With no login route configured, send them back where they were: the
        // app's own auth middleware knows better than we do whether that page
        // needs a login.
        return $this->urlFromConfig('local_login_route') ?? $request->fullUrl();
    }

    private function urlFromConfig(string $key): ?string
    {
        $value = $this->config->get('exoclass-sso.'.$key);

        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        $value = trim($value);

        if (str_contains($value, '://') || str_starts_with($value, '/')) {
            return url($value);
        }

        return Route::has($value) ? route($value) : null;
    }

    private function isAt(Request $request, string $url): bool
    {
        return rtrim($request->url(), '/') === rtrim(strtok($url, '?') ?: $url, '/');
    }
}
