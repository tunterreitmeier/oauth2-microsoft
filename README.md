# Microsoft OAuth2 Provider for PHP League OAuth2 Client

[![CI](https://github.com/wikando/oauth2-microsoft/workflows/CI/badge.svg)](https://github.com/wikando/oauth2-microsoft/actions)
[![Latest Stable Version](https://img.shields.io/packagist/v/wikando/oauth2-microsoft.svg)](https://packagist.org/packages/wikando/oauth2-microsoft)
[![License](https://img.shields.io/packagist/l/wikando/oauth2-microsoft.svg)](LICENSE)

A production-ready Microsoft OAuth2 provider package for [thephpleague/oauth2-client](https://github.com/thephpleague/oauth2-client), enabling authentication via Microsoft Entra (Azure AD) with support for both personal and organizational accounts.

## Features

- **Microsoft Graph API integration**: Fetches comprehensive user data from Microsoft Graph
- **Flexible tenant support**: Common, organizations-only, consumers-only, or specific tenant
- **OpenID Connect support**: Helper methods to access ID token claims

## Requirements

- PHP 8.2 or higher
- league/oauth2-client ^2.6.0

## Installation

```bash
composer require unt/oauth2-microsoft
```

## Usage

### Basic Usage

Default tenant is `common` which will work for both personal and work accounts.

```php
use Unt\OAuth2\Client\Provider\Microsoft;

$provider = new Microsoft([
    'clientId'     => '{microsoft-client-id}',
    'clientSecret' => '{microsoft-client-secret}',
    'redirectUri'  => 'https://example.com/callback',
]);

// Get authorization URL
$authorizationUrl = $provider->getAuthorizationUrl();

// Save state for CSRF protection
$_SESSION['oauth2state'] = $provider->getState();

// Redirect user to authorization URL
header('Location: ' . $authorizationUrl);
exit;
```

### Handle Callback

```php
// Verify state for CSRF protection
if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
    unset($_SESSION['oauth2state']);
    exit('Invalid state');
}

try {
    // Get access token
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Get user details from Microsoft Graph API
    $resourceOwner = $provider->getResourceOwner($token);

    echo 'Hello, ' . $resourceOwner->getDisplayName() . '!';
    echo 'Email: ' . $resourceOwner->getEmail();
    echo 'User ID: ' . $resourceOwner->getId();

} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    exit('Authentication failed: ' . $e->getMessage());
}
```

### Tenant Selection

#### Organizations Only (Work/School Accounts)

```php
use Wikando\OAuth2\Client\Provider\Microsoft;

$provider = new Microsoft([
    'clientId'     => '{microsoft-client-id}',
    'clientSecret' => '{microsoft-client-secret}',
    'redirectUri'  => 'https://example.com/callback',
    'tenant'       => Microsoft::TENANT_ORGANIZATIONS,
]);
```

#### Specific Tenant

```php
$provider = new Microsoft([
    'clientId'     => '{microsoft-client-id}',
    'clientSecret' => '{microsoft-client-secret}',
    'redirectUri'  => 'https://example.com/callback',
    'tenant'       => '12345678-1234-1234-1234-123456789012', // Your tenant ID
]);
```

### Accessing ID Token Claims

If you need access to the OpenID Connect ID token claims (e.g., tenant ID, authentication metadata), use the helper method:

```php
// Request OpenID Connect scopes when getting authorization URL
use new \Wikando\OAuth2\Client\Provider\MicrosoftProvider;

$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => array_merge(
        ['openid', 'profile', 'email']
        ['User.Read']
    )
]);

// or use helper method
$provider = (MicrosoftProvider([])->requireOpenIdScopes();

// After getting the access token
$token = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);

// Decode ID token claims
$claims = $provider->getIdTokenClaims($token);

echo 'Tenant ID: ' . $claims['tid'];
echo 'Object ID: ' . $claims['oid'];
echo 'Authentication method: ' . $claims['amr'][0];
```

### Additional Scopes

Request additional Microsoft Graph API permissions:

```php
$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'User.Read', 'Calendars.Read', 'Mail.Read']
]);
```

### Refresh Tokens

To get a refresh token, include the `offline_access` scope:

```php
$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'User.Read', 'offline_access']
]);

// Later, refresh the token
$newToken = $provider->getAccessToken('refresh_token', [
    'refresh_token' => $token->getRefreshToken()
]);
```

## Resource Owner Methods

The `MicrosoftResourceOwner` object fetched from Microsoft Graph API provides:

| Method                   | Description            | Example Value         |
|--------------------------|------------------------|-----------------------|
| `getId()`                | User unique identifier | `"12345678-abcd-..."` |
| `getUserPrincipalName()` | Email-like identifier  | `"user@company.com"`  |
| `getDisplayName()`       | Full name              | `"John Doe"`          |
| `getGivenName()`         | First name             | `"John"`              |
| `getSurname()`           | Last name              | `"Doe"`               |
| `getEmail()`             | Email address *        | `"john@company.com"`  |
| `getJobTitle()`          | Job title              | `"Software Engineer"` |
| `getOfficeLocation()`    | Office location        | `"Building 42"`       |
| `getMobilePhone()`       | Mobile phone           | `"+1234567890"`       |
| `getBusinessPhones()`    | List of phone numbers  | `["+1234567890"]`     |
| `getPreferredLanguage()` | Locale preference      | `"en-US"`             |
| `toArray()`              | All data as array      | `array(...)`          |


## Testing

Run the test suite:

```bash
composer test           # Run PHPUnit tests
composer test-coverage  # Run tests with HTML coverage report
composer check:static   # Run static analysis (PHPStan level 8)
composer check:style    # Check code style (PSR-12)
composer fix:style      # Fix code style issues
composer check          # Run all checks (style, PHPStan, tests)
```

## Contributing

Contributions are welcome! Please fork and create a PR.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Resources

- [Microsoft Identity Platform Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/)
- [OAuth 2.0 and OpenID Connect on Azure AD](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols)
- [PHP League OAuth2 Client](https://github.com/thephpleague/oauth2-client)
