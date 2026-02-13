<?php

declare(strict_types=1);

namespace Unt\OAuth2\Client\Token;

final class IdToken
{
    /**
     * @param array<string, int|string> $fullPayload
     */
    public function __construct(
        public string $tenantId,
        public ?string $name,
        public ?string $preferredUsername,
        public ?string $email,
        public array $fullPayload,
    ) {}

    public static function fromPayload(string $payload): self
    {
        $data = json_decode($payload, true) ?: throw new \RuntimeException('Failed to decode JWT payload.');

        return new self(
            $data['tid'],
            $data['name'] ?? null,
            $data['preferred_username'] ?? null,
            $data['email'] ?? null,
            $data,
        );
    }
}
