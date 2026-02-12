<?php

declare(strict_types=1);

namespace Unt\OAuth2\Client\Test\Provider;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Unt\OAuth2\Client\Provider\MicrosoftResourceOwner;

#[CoversClass(MicrosoftResourceOwner::class)]
class MicrosoftResourceOwnerTest extends TestCase
{
    public function testGettersWithFullData(): void
    {
        $data = [
            'id' => '12345',
            'userPrincipalName' => 'user@example.com',
            'displayName' => 'Test User',
            'givenName' => 'Test',
            'surname' => 'User',
            'mail' => 'user@example.com', // Graph API uses 'mail', not 'email'
            'jobTitle' => 'Developer',
            'officeLocation' => 'Building 1',
            'mobilePhone' => '+1234567890',
            'preferredLanguage' => 'en-US',
            'businessPhones' => [
                '+99999999',
            ],
        ];

        $resourceOwner = new MicrosoftResourceOwner($data);

        $this->assertSame('12345', $resourceOwner->getId());
        $this->assertSame('user@example.com', $resourceOwner->getUserPrincipalName());
        $this->assertSame('Test User', $resourceOwner->getDisplayName());
        $this->assertSame('Test', $resourceOwner->getGivenName());
        $this->assertSame('User', $resourceOwner->getSurname());
        $this->assertSame('user@example.com', $resourceOwner->getEmail());
        $this->assertSame('Developer', $resourceOwner->getJobTitle());
        $this->assertSame('Building 1', $resourceOwner->getOfficeLocation());
        $this->assertSame('+1234567890', $resourceOwner->getMobilePhone());
        $this->assertSame('en-US', $resourceOwner->getPreferredLanguage());
        $this->assertSame(['+99999999'], $resourceOwner->getBusinessPhones());
    }

    public function testGettersWithMissingData(): void
    {
        $data = [
            'id' => '12345',
            'displayName' => 'Test User',
            'userPrincipalName' => 'foo@bar.com',
        ];

        $resourceOwner = new MicrosoftResourceOwner($data);

        $this->assertSame('12345', $resourceOwner->getId());
        $this->assertSame('Test User', $resourceOwner->getDisplayName());
        $this->assertSame('foo@bar.com', $resourceOwner->getUserPrincipalName());
        $this->assertSame('foo@bar.com', $resourceOwner->getEmail());
        $this->assertNull($resourceOwner->getGivenName());
        $this->assertNull($resourceOwner->getSurname());
        $this->assertNull($resourceOwner->getJobTitle());
        $this->assertNull($resourceOwner->getOfficeLocation());
        $this->assertNull($resourceOwner->getMobilePhone());
        $this->assertNull($resourceOwner->getPreferredLanguage());
        $this->assertEmpty($resourceOwner->getBusinessPhones());
    }

    public function testToArray(): void
    {
        $data = [
            'id' => '12345',
            'displayName' => 'Test User',
            'email' => 'user@example.com',
        ];

        $resourceOwner = new MicrosoftResourceOwner($data);

        $this->assertSame($data, $resourceOwner->toArray());
    }
}
