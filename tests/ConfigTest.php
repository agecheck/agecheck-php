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

namespace AgeCheck\Tests;

use AgeCheck\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testRejectsShortHmacSecret(): void
    {
        $this->expectException(\RuntimeException::class);
        new Config([
            'hmacSecret' => 'too-short',
        ]);
    }

    public function testRejectsInvalidDeploymentMode(): void
    {
        $this->expectException(\RuntimeException::class);
        new Config([
            'hmacSecret' => str_repeat('a', 32),
            'deploymentMode' => 'invalid',
        ]);
    }

    public function testRejectsInvalidRequiredAge(): void
    {
        $this->expectException(\RuntimeException::class);
        new Config([
            'hmacSecret' => str_repeat('a', 32),
            'requiredAge' => -1,
        ]);
    }

    public function testRejectsNonPositiveCookieTtl(): void
    {
        $this->expectException(\RuntimeException::class);
        new Config([
            'hmacSecret' => str_repeat('a', 32),
            'cookieTtl' => 0,
        ]);
    }

    public function testDefaultsToAgeCheckJwksEndpoint(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('a', 32),
        ]);

        $this->assertSame('https://agecheck.me/.well-known/jwks.json', $config->jwksUrl);
    }

    public function testDefaultsToDemoJwksEndpointInDemoMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('a', 32),
            'deploymentMode' => Config::DEPLOYMENT_DEMO,
        ]);

        $this->assertSame('https://demo.agecheck.me/.well-known/jwks.json', $config->jwksUrl);
    }

    public function testRejectsCustomJwksWithoutExplicitOptIn(): void
    {
        $this->expectException(\RuntimeException::class);
        new Config([
            'hmacSecret' => str_repeat('a', 32),
            'jwksUrl' => 'https://issuer.example/.well-known/jwks.json',
        ]);
    }

    public function testRejectsNonHttpsJwksUrl(): void
    {
        $this->expectException(\RuntimeException::class);
        new Config([
            'hmacSecret' => str_repeat('a', 32),
            'allowCustomIssuer' => true,
            'jwksUrl' => 'http://issuer.example/.well-known/jwks.json',
            'issuer' => 'did:web:issuer.example',
        ]);
    }

    public function testAllowsCustomJwksWithExplicitOptIn(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('a', 32),
            'allowCustomIssuer' => true,
            'jwksUrl' => 'https://issuer.example/.well-known/jwks.json',
            'issuer' => 'did:web:issuer.example',
        ]);

        $this->assertTrue($config->allowCustomIssuer);
        $this->assertSame('https://issuer.example/.well-known/jwks.json', $config->jwksUrl);
    }
}
