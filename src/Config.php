<?php
/*
 * AgeCheck-php
 * Copyright (c) 2026 ReallyMe LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace AgeCheck;

final class Config
{
    public const DEPLOYMENT_PRODUCTION = 'production';
    public const DEPLOYMENT_DEMO = 'demo';
    public const DEFAULT_PRODUCTION_ISSUER = 'did:web:agecheck.me';
    public const DEFAULT_DEMO_ISSUER = 'did:web:demo.agecheck.me';
    public const DEFAULT_PRODUCTION_JWKS_URL = 'https://agecheck.me/.well-known/jwks.json';
    public const DEFAULT_DEMO_JWKS_URL = 'https://demo.agecheck.me/.well-known/jwks.json';

    public bool $allowCustomIssuer = false;

    // Verification and gate behavior are unified under one deployment mode.
    public string $deploymentMode = self::DEPLOYMENT_PRODUCTION;
    /** @var string|string[]|null */
    public $issuer = null;
    public ?string $jwksUrl = null;

    // Gate behavior
    public string $gatePage = '/ageverify';      // Page that launches AgeCheck popup
    public string $verifyApi = '/ageverify/api'; // Backend endpoint that receives JWT
    public string $gateHeaderName = 'X-Age-Gate';
    public string $gateHeaderRequiredValue = 'true';

    // Session/cookie
    public string $cookieName = 'agecheck_verified';
    public int $cookieTtl = 86400; // 1 day
    public string $hmacSecret;     // MUST be set

    // Policy
    public int $requiredAge = 18; // Minimum accepted age tier (e.g. 18 accepts 18+, 21+, 65+)

    public function __construct(array $opts = [])
    {
        foreach ($opts as $key => $value) {
            if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }

        if (empty($this->hmacSecret)) {
            throw new \RuntimeException('AgeCheck Config requires hmacSecret.');
        }
        if (strlen($this->hmacSecret) < 32) {
            throw new \RuntimeException('hmacSecret must be at least 32 bytes.');
        }

        if (!in_array($this->deploymentMode, [self::DEPLOYMENT_PRODUCTION, self::DEPLOYMENT_DEMO], true)) {
            throw new \RuntimeException('Invalid deploymentMode. Expected production or demo.');
        }

        if ($this->requiredAge < 0) {
            throw new \RuntimeException('requiredAge must be a non-negative integer.');
        }
        if ($this->cookieTtl <= 0) {
            throw new \RuntimeException('cookieTtl must be a positive integer (seconds).');
        }

        $defaultJwksUrl = $this->deploymentMode === self::DEPLOYMENT_DEMO
            ? self::DEFAULT_DEMO_JWKS_URL
            : self::DEFAULT_PRODUCTION_JWKS_URL;
        $jwksUrl = $this->jwksUrl ?? $defaultJwksUrl;

        $jwksParts = parse_url($jwksUrl);
        if (!is_array($jwksParts) || ($jwksParts['scheme'] ?? null) !== 'https') {
            throw new \RuntimeException('jwksUrl must be a valid https URL.');
        }

        $defaultIssuers = $this->deploymentMode === self::DEPLOYMENT_DEMO
            ? [self::DEFAULT_DEMO_ISSUER, self::DEFAULT_PRODUCTION_ISSUER]
            : [self::DEFAULT_PRODUCTION_ISSUER];

        if (!$this->allowCustomIssuer) {
            if (!hash_equals($defaultJwksUrl, $jwksUrl)) {
                throw new \RuntimeException(
                    'Custom jwksUrl is disabled by default. Set allowCustomIssuer=true to override.'
                );
            }

            if ($this->issuer !== null) {
                throw new \RuntimeException(
                    'Custom issuer is disabled by default. Set allowCustomIssuer=true to override.'
                );
            }
        }

        $this->jwksUrl = $jwksUrl;
    }

    /**
     * @return array<int,string>
     */
    public function expectedIssuers(): array
    {
        if (is_string($this->issuer) && $this->issuer !== '') {
            return [$this->issuer];
        }
        if (is_array($this->issuer)) {
            $out = [];
            foreach ($this->issuer as $item) {
                if (!is_string($item) || $item === '') {
                    throw new \RuntimeException('issuer array must contain non-empty strings only.');
                }
                $out[] = $item;
            }
            if (count($out) > 0) {
                return $out;
            }
        }

        return $this->deploymentMode === self::DEPLOYMENT_DEMO
            ? [self::DEFAULT_DEMO_ISSUER, self::DEFAULT_PRODUCTION_ISSUER]
            : [self::DEFAULT_PRODUCTION_ISSUER];
    }

    /**
     * @return array<int,string>
     */
    public function jwksUrls(): array
    {
        if (!is_string($this->jwksUrl) || $this->jwksUrl === '') {
            throw new \RuntimeException('jwksUrl must be configured.');
        }

        if ($this->deploymentMode === self::DEPLOYMENT_DEMO
            && !hash_equals(self::DEFAULT_PRODUCTION_JWKS_URL, $this->jwksUrl)) {
            return [$this->jwksUrl, self::DEFAULT_PRODUCTION_JWKS_URL];
        }

        return [$this->jwksUrl];
    }
}
