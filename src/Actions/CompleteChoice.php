<?php

declare(strict_types=1);

namespace ExoClass\Sso\Actions;

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Contracts\IdentityResolver;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Http\CredentialReader;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Resolution\Resolution;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Support\SsoLogger;
use Illuminate\Http\Request;
use Throwable;

/**
 * The other half of the picker: the visitor chose, and this turns that choice
 * into a session.
 *
 * The middleware stashed the candidates and sent them to the app's picker page;
 * the app renders {@see SsoSession::candidates()} and posts the chosen key back
 * here. This re-proves the ExoClass session upstream — the choice arrives on a
 * later request and nothing about the earlier probe may be assumed still true —
 * and hands the key to the app's resolver, which is required to re-derive the
 * candidate list and reject anything not in it. A key from a browser is a
 * request, never a fact.
 *
 * Returns the resolution so the app can decide what the visitor sees. On an
 * {@see Authenticated} the session is already established and the intended URL
 * is waiting in {@see SsoSession::pullIntendedUrl()}.
 */
final readonly class CompleteChoice
{
    public function __construct(
        private IdentityFetcher $fetcher,
        private IdentityResolver $resolver,
        private CredentialReader $credentials,
        private SsoLogger $logger,
    ) {}

    public function handle(Request $request, string $candidateKey): Resolution
    {
        $credential = $this->credentials->from($request);

        if ($credential === null) {
            return new Denied('no ExoClass session cookie on the request that made the choice');
        }

        try {
            $identity = $this->fetcher->fetch($credential);
        } catch (UnauthorizedException) {
            return new Denied('ExoClass no longer recognises this session');
        } catch (Throwable $exception) {
            $this->logger->warning('ExoClass SSO could not confirm a choice upstream.', [
                'exception' => $exception::class,
                'reason' => $exception->getMessage(),
            ], $credential->redactable());

            // Not a refusal of this person — a refusal to guess. The app should
            // say "try again", not "you have no access".
            return new Denied('ExoClass could not be reached to confirm the choice');
        }

        $resolution = $this->resolver->resolveChoice($identity, $candidateKey);

        if (! $resolution instanceof Authenticated) {
            $this->logger->warning('ExoClass SSO refused a picked candidate.', [
                'exoclass_user_id' => $identity->user->id,
                'candidate' => $candidateKey,
                'resolution' => $resolution::class,
            ], $credential->redactable());

            return $resolution;
        }

        SsoSession::establish($request, $resolution->user, $credential, $identity);

        $this->logger->info('ExoClass SSO signed a visitor in through the picker.', [
            'exoclass_user_id' => $identity->user->id,
            'email' => $identity->user->email,
            'candidate' => $candidateKey,
        ], $credential->redactable());

        return $resolution;
    }
}
