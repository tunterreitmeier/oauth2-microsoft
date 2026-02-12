<?php

declare(strict_types=1);

namespace Unt\OAuth2\Client\Test\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Unt\OAuth2\Client\Provider\MicrosoftProvider;
use Unt\OAuth2\Client\Provider\MicrosoftResourceOwner;

#[CoversClass(MicrosoftProvider::class)]
class MicrosoftProviderTest extends TestCase
{
    private MicrosoftProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new MicrosoftProvider([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_secret',
            'redirectUri' => 'https://example.com/callback',
        ]);
    }

    #[TestWith([MicrosoftProvider::TENANT_ORGANIZATIONS])]
    #[TestWith([MicrosoftProvider::TENANT_COMMON])]
    #[TestWith([MicrosoftProvider::TENANT_CONSUMERS])]
    #[TestWith(['dummy-tenant-id'])]
    public function testAuthorizationUrl(string $tenant): void
    {
        $url = $this->provider->withTenant($tenant)->getAuthorizationUrl();
        $uri = parse_url($url);
        $this->assertIsArray($uri);

        $this->assertSame('/' . $tenant . '/oauth2/v2.0/authorize', $uri['path']);
        $this->assertSame('login.microsoftonline.com', $uri['host']);
    }

    public function testBaseAccessTokenUrl(): void
    {
        $this->assertSame(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            $this->provider->getBaseAccessTokenUrl([]),
        );
    }

    public function testDefaultOpenIdScopes(): void
    {
        $url = $this->provider->requireOpenIdScopes()->getAuthorizationUrl();
        $queryString = parse_url($url, PHP_URL_QUERY);
        $this->assertIsString($queryString);
        parse_str($queryString, $query);

        $this->assertArrayHasKey('scope', $query);

        $scopes = explode(' ', $query['scope']);
        $this->assertEqualsCanonicalizing(['openid', 'profile', 'email'], $scopes);
    }

    public function testRequireUserReadScopes(): void
    {
        $url = $this->provider->requireUserReadScope()->getAuthorizationUrl();
        $queryString = parse_url($url, PHP_URL_QUERY);
        $this->assertIsString($queryString);
        parse_str($queryString, $query);

        $this->assertArrayHasKey('scope', $query);
        $this->assertSame('User.Read', $query['scope']);
    }

    public function testRequireOfflineAccess(): void
    {
        $url = $this->provider->requireOfflineAccess()->getAuthorizationUrl();
        $queryString = parse_url($url, PHP_URL_QUERY);
        $this->assertIsString($queryString);
        parse_str($queryString, $query);

        $this->assertArrayHasKey('scope', $query);
        $this->assertSame('offline_access', $query['scope']);
    }

    public function testErrorResponse(): void
    {
        $jsonBody = json_encode([
            'error' => 'invalid_request',
            'error_description' => 'The request is missing a required parameter',
        ]);
        $this->assertIsString($jsonBody);

        $mock = new MockHandler([
            new Response(400, [], $jsonBody),
        ]);

        $provider = new MicrosoftProvider(
            [
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_client_secret',
                'redirectUri' => 'https://example.com/callback',
            ],
            [
                'httpClient' => new Client(['handler' => HandlerStack::create($mock)]),
            ],
        );

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('The request is missing a required parameter');

        $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
    }

    public function testGetAccessToken(): void
    {
        $jsonBody = json_encode([
            'access_token' => 'mock_access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'mock_refresh_token',
        ]);
        $this->assertIsString($jsonBody);

        $mock = new MockHandler([
            new Response(200, [], $jsonBody),
        ]);

        $provider = new MicrosoftProvider(
            [
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_client_secret',
                'redirectUri' => 'https://example.com/callback',
            ],
            [
                'httpClient' => new Client(['handler' => HandlerStack::create($mock)]),
            ],
        );

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);

        $this->assertInstanceOf(AccessToken::class, $token);
        $this->assertSame('mock_access_token', $token->getToken());
        $this->assertSame('mock_refresh_token', $token->getRefreshToken());
    }

    public function testGetResourceOwnerWithGraphApiStrategy(): void
    {
        $tokenJson = json_encode([
            'access_token' => 'mock_access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);
        $this->assertIsString($tokenJson);

        $userJson = json_encode([
            'id' => '12345',
            'userPrincipalName' => 'user@example.com',
            'displayName' => 'Test User',
            'givenName' => 'Test',
            'surname' => 'User',
            'mail' => 'user@example.com',
        ]);
        $this->assertIsString($userJson);

        $mock = new MockHandler([
            new Response(200, [], $tokenJson),
            new Response(200, [], $userJson),
        ]);

        $provider = new MicrosoftProvider(
            [
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_client_secret',
                'redirectUri' => 'https://example.com/callback',
            ],
            [
                'httpClient' => new Client(['handler' => HandlerStack::create($mock)]),
            ],
        );

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
        $this->assertInstanceOf(AccessToken::class, $token);
        $resourceOwner = $provider->getResourceOwner($token);

        $this->assertInstanceOf(MicrosoftResourceOwner::class, $resourceOwner);
        $this->assertSame('12345', $resourceOwner->getId());
        $this->assertSame('Test User', $resourceOwner->getDisplayName());
        $this->assertSame('user@example.com', $resourceOwner->getEmail());
    }

    public function testGetIdTokenClaims(): void
    {
        $claims = [
            'oid' => '67890',
            'sub' => 'sub-67890',
            'preferred_username' => 'idtoken@example.com',
            'name' => 'ID Token User',
            'given_name' => 'ID Token',
            'family_name' => 'User',
            'email' => 'idtoken@example.com',
            'tid' => 'tenant-456',
            'locale' => 'de-DE',
        ];

        $payload = base64_encode(json_encode($claims));
        $idToken = 'header.' . strtr($payload, '+/', '-_') . '.signature';

        $responsePayload = json_encode([
            'access_token' => 'mock_access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => $idToken,
        ]);

        $mock = new MockHandler([
            new Response(200, [], $responsePayload),
        ]);

        $provider = new MicrosoftProvider(
            [
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_client_secret',
                'redirectUri' => 'https://example.com/callback',
            ],
            [
                'httpClient' => new Client(['handler' => HandlerStack::create($mock)]),
            ],
        );

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);
        $decodedClaims = $provider->getIdTokenClaims($token);

        $this->assertSame($claims, $decodedClaims);
        $this->assertSame('67890', $decodedClaims['oid']);
        $this->assertSame('idtoken@example.com', $decodedClaims['email']);
        $this->assertSame('tenant-456', $decodedClaims['tid']);
    }

    public function testGetIdTokenClaimsThrowsExceptionWhenMissing(): void
    {
        $responsePayload = json_encode([
            'access_token' => 'mock_access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $mock = new MockHandler([
            new Response(200, [], $responsePayload),
        ]);

        $provider = new MicrosoftProvider(
            [
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_client_secret',
                'redirectUri' => 'https://example.com/callback',
            ],
            [
                'httpClient' => new Client(['handler' => HandlerStack::create($mock)]),
            ],
        );

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ID token not found in token response');

        $provider->getIdTokenClaims($token);
    }

    public function testGetIdTokenClaimsThrowsExceptionForMalformedJwt(): void
    {
        $responsePayload = json_encode([
            'access_token' => 'mock_access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => 'invalid.jwt', // Malformed JWT
        ]);

        $mock = new MockHandler([
            new Response(200, [], $responsePayload),
        ]);

        $provider = new MicrosoftProvider(
            [
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_client_secret',
                'redirectUri' => 'https://example.com/callback',
            ],
            [
                'httpClient' => new Client(['handler' => HandlerStack::create($mock)]),
            ],
        );

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_code']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Malformed JWT ID token');

        $provider->getIdTokenClaims($token);
    }
}
