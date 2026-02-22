# Microsoft OAuth2 Provider for PHP League OAuth2 Client

[![CI](https://github.com/tunterreitmeier/oauth2-microsoft/workflows/CI/badge.svg)](https://github.com/tunterreitmeier/oauth2-microsoft/actions)
[![Latest Stable Version](https://img.shields.io/packagist/v/untt/oauth2-microsoft.svg)](https://packagist.org/packages/untt/oauth2-microsoft)
[![License](https://img.shields.io/github/license/tunterreitmeier/oauth2-microsoft)](LICENSE)

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
composer require untt/oauth2-microsoft
```

## Usage

### Basic Usage

Default tenant is `common` which will work for both personal and work accounts.

```php
use Unt\OAuth2\Client\Provider\MicrosoftProvider;

$provider = new MicrosoftProvider([
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
use Unt\OAuth2\Client\Provider\MicrosoftProvider;

$provider = new MicrosoftProvider([
    'clientId'     => '{microsoft-client-id}',
    'clientSecret' => '{microsoft-client-secret}',
    'redirectUri'  => 'https://example.com/callback',
    'tenant'       => Microsoft::TENANT_ORGANIZATIONS,
]);
```

#### Specific Tenant

```php
$provider = new MicrosoftProvider([
    'clientId'     => '{microsoft-client-id}',
    'clientSecret' => '{microsoft-client-secret}',
    'redirectUri'  => 'https://example.com/callback',
    'tenant'       => '12345678-1234-1234-1234-123456789012', // Your tenant ID
]);
```

### Accessing ID Token Claims

If you need access to the OpenID Connect ID token claims (e.g., tenant ID, authentication metadata), you can add them to the scopes.

```php
// Request OpenID Connect scopes when getting authorization URL
use new \Unt\OAuth2\Client\Provider\MicrosoftProvider;

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
$idToken = $provider->getIdTokenClaims($token);

echo 'Tenant ID: ' . $idToken->tenantId;
echo 'Name: ' . $idToken->name;
echo 'Username: ' . $idToken->preferredUsername;
echo 'Email: ' . $idToken->email;

// full token payload: $idToken->fullPayload

```

Please note that the OpenID Connect JWT is not actively verified. Just as with the Access Token, you should
verify the `state` to detect forged requests.

### Additional Scopes

Request additional Microsoft Graph API permissions:

```php
$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'User.Read', 'Calendars.Read', 'Mail.Read']
]);
```

Please note that Microsoft usually does not allow scopes across different 'product spaces'.
So if you require for example `User.Read` from `https://graph.microsoft.com`, you will not be able to request `SMTP.Send`
from `https://outlook.office.com` in the same token. You will have to request these individually, using a refresh token.

### Refresh Tokens

To get a refresh token, include the `offline_access` scope:

```php
$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => ['openid', 'User.Read', 'offline_access']
]);

// Store the refresh token
$token->getRefreshToken();

// Later, refresh the token
if ($token->hasExpired()) {
    $newToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $token->getRefreshToken()
    ]);
    
    // store the new refresh token, in case it also has expired
} 

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

GNU General Public License version 3 License. See [LICENSE](LICENSE) for details.

## Resources

- [Microsoft Identity Platform Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/)
- [OAuth 2.0 and OpenID Connect on Azure AD](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols)
- [PHP League OAuth2 Client](https://github.com/thephpleague/oauth2-client)
