<?php

declare(strict_types=1);

namespace Unt\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Represents a Microsoft resource owner (user) from Microsoft Graph API.
 *
 * Contains user information fetched from https://graph.microsoft.com/v1.0/me
 */
final readonly class MicrosoftResourceOwner implements ResourceOwnerInterface
{
    /**
     * @param array<string, mixed> $response Graph API user response
     */
    public function __construct(private array $response) {}

    public function getId(): string
    {
        return $this->response['id'];
    }

    public function getUserPrincipalName(): string
    {
        return $this->response['userPrincipalName'];
    }

    public function getDisplayName(): ?string
    {
        return $this->response['displayName'];
    }

    public function getGivenName(): ?string
    {
        return $this->response['givenName'] ?? null;
    }

    public function getSurname(): ?string
    {
        return $this->response['surname'] ?? null;
    }

    public function getEmail(): ?string
    {
        return $this->response['mail'] ?? $this->response['userPrincipalName'] ?? null;
    }

    public function getJobTitle(): ?string
    {
        return $this->response['jobTitle'] ?? null;
    }

    public function getOfficeLocation(): ?string
    {
        return $this->response['officeLocation'] ?? null;
    }

    public function getMobilePhone(): ?string
    {
        return $this->response['mobilePhone'] ?? null;
    }

    public function getPreferredLanguage(): ?string
    {
        return $this->response['preferredLanguage'] ?? null;
    }

    /** @return string[] */
    public function getBusinessPhones(): array
    {
        return $this->response['businessPhones'] ?? [];
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->response;
    }
}
