<?php

declare(strict_types=1);

namespace Unt\OAuth2\Client\Provider;

use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\OptionProvider\OptionProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Tool\RequestFactory;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Unt\OAuth2\Client\Token\IdToken;

/**
 * Microsoft OAuth2 Provider.
 *
 * Supports authentication via Microsoft Entra (Azure AD) for personal,
 * organizational, or both account types. Always fetches user data from
 * Microsoft Graph API.
 */
final class MicrosoftProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /** @var string supports both personal and work/school accounts. */
    public const TENANT_COMMON = 'common';

    /** @var string supports only work/school accounts. */
    public const TENANT_ORGANIZATIONS = 'organizations';

    /** @var string supports only personal accounts. */
    public const TENANT_CONSUMERS = 'consumers';

    /** @var string This scope is required to fetch user data via Graph API */
    public const SCOPE_USER_READ = 'User.Read';

    /** @var string This scope is required to get a refresh token */
    public const SCOPE_OFFLINE_ACCESS = 'offline_access';

    /** @var string[] This scope is required to fetch user data from the OpenID token */
    public const SCOPES_OPEN_ID = ['openid', 'profile', 'email'];

    private string $tenant = self::TENANT_COMMON;

    /** @var string[] */
    private array $defaultScopes = [];

    /** @method MicrosoftResourceOwner getResourceOwner() */

    /**
     * @param array{
     *     clientId: string,
     *     clientSecret: string,
     *     redirectUri: string,
     *     tenant?: 'common'|'organizations'|'consumers'|string,
     *     state?: string,
     *     pkceCode?: ?string,
     *     timeout?: float,
     *     proxy?: string
     * } $options Use 'tenant' to use for all requests - see parent for all options
     * @param array{
     *     grantFactory?: GrantFactory,
     *     requestFactory?: RequestFactory,
     *     httpClient?: ClientInterface,
     *     optionProvider?: OptionProviderInterface
     * } $collaborators See parent
     * @phpstan-ignore parameter.defaultValue
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (isset($options['tenant'])) {
            $this->tenant = $options['tenant'];
            unset($options['tenant']);
        }

        parent::__construct($options, $collaborators);
    }


    public function withTenant(string $tenant): self
    {
        $this->tenant = $tenant;

        return $this;
    }

    /** Use this method to always require open id scopes with your token requests */
    public function requireOpenIdScopes(): self
    {
        $this->defaultScopes = \array_merge($this->defaultScopes, self::SCOPES_OPEN_ID);

        return $this;
    }

    /** Use this method to always require open id scopes with your token requests */
    public function requireUserReadScope(): self
    {
        $this->defaultScopes[] = self::SCOPE_USER_READ;

        return $this;
    }

    /** Use this method if you want a refresh token to keep using the grant */
    public function requireOfflineAccess(): self
    {
        $this->defaultScopes[] = self::SCOPE_OFFLINE_ACCESS;

        return $this;
    }

    /**
     * Extract and decode the ID token payload from an access token.
     * The ID token must be present in the token response (requires 'openid' scope).
     *
     * @throws RuntimeException If ID token is missing or cannot be decoded
     */
    public function getIdTokenClaims(AccessToken $token): IdToken
    {
        $values = $token->getValues();
        $idToken = $values['id_token'] ?? null;

        if ($idToken === null) {
            throw new RuntimeException(
                'ID token not found in token response. Ensure "openid" scope is requested.',
            );
        }

        // Parse JWT (format: header.payload.signature)
        $parts = explode('.', $idToken);

        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed JWT ID token.');
        }

        // Decode the payload (no signature verification needed - token comes via HTTPS)
        $payload = base64_decode(strtr($parts[1], '-_', '+/'), true);

        if ($payload === false) {
            throw new RuntimeException('Failed to decode JWT payload.');
        }

        return IdToken::fromPayload($payload);
    }

    /**
     * @inheritDoc
     */
    public function getBaseAuthorizationUrl(): string
    {
        return sprintf('https://login.microsoftonline.com/%s/oauth2/v2.0/authorize', $this->tenant);
    }

    /**
     * @inheritDoc
     * @param array<string, mixed> $params
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return sprintf('https://login.microsoftonline.com/%s/oauth2/v2.0/token', $this->tenant);
    }

    /**
     * @inheritDoc
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return 'https://graph.microsoft.com/v1.0/me';
    }

    /**
     * @inheritDoc
     * @return array<string>
     */
    protected function getDefaultScopes(): array
    {
        return $this->defaultScopes;
    }

    /**
     * @inheritDoc
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * @inheritDoc
     * @param array<string, mixed>|string $data
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['error'])) {
            $error = $data['error'];
            $errorDescription = $data['error_description'] ?? $error;

            throw new IdentityProviderException(
                $errorDescription,
                $response->getStatusCode(),
                $data,
            );
        }
    }

    /**
     * @inheritDoc
     * @param array<string, mixed> $response
     */
    protected function createResourceOwner(array $response, AccessToken $token): MicrosoftResourceOwner
    {
        return new MicrosoftResourceOwner($response);
    }
}
