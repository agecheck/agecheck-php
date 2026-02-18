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
use AgeCheck\ErrorCode;
use AgeCheck\Tests\Support\StaticKeyCache;
use AgeCheck\Verifier;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

final class VerifierTest extends TestCase
{
    private string $privatePem;
    /** @var array<string,mixed> */
    private array $jwks;

    protected function setUp(): void
    {
        parent::setUp();

        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $this->assertNotFalse($key, 'Unable to create EC key pair for test');

        $privateOut = '';
        $ok = openssl_pkey_export($key, $privateOut);
        $this->assertTrue($ok, 'Unable to export private key for test');

        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details, 'Unable to read public key details for test');

        $this->privatePem = $privateOut;
        $this->jwks = [
            'keys' => [
                $this->createJwkFromPublicDetails($details, 'k1'),
            ],
        ];
    }

    public function testVerifyAcceptsProductionCredential(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'deploymentMode' => Config::DEPLOYMENT_PRODUCTION,
            'requiredAge' => 18,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '18+');

        $result = $verifier->verify($jwt);

        $this->assertTrue($result->isOk());
        $this->assertNull($result->error());
    }

    public function testVerifyRejectsDemoIssuerInProductionMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'deploymentMode' => Config::DEPLOYMENT_PRODUCTION,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:demo.agecheck.me', '21+');

        $result = $verifier->verify($jwt);

        $this->assertFalse($result->isOk());
        $this->assertSame(ErrorCode::INVALID_ISSUER, $result->code());
        $this->assertSame('Invalid issuer', $result->error());
    }

    public function testVerifyAcceptsDemoIssuerInDemoMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'deploymentMode' => Config::DEPLOYMENT_DEMO,
            'requiredAge' => 18,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:demo.agecheck.me', '21+');

        $result = $verifier->verify($jwt);

        $this->assertTrue($result->isOk());
    }

    public function testVerifyAcceptsProductionIssuerInDemoMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'deploymentMode' => Config::DEPLOYMENT_DEMO,
            'requiredAge' => 18,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '21+');

        $result = $verifier->verify($jwt);

        $this->assertTrue($result->isOk());
    }

    public function testVerifyRejectsInsufficientAgeTier(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'requiredAge' => 21,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '18+');

        $result = $verifier->verify($jwt);

        $this->assertFalse($result->isOk());
        $this->assertSame(ErrorCode::INSUFFICIENT_AGE_TIER, $result->code());
        $this->assertSame('Insufficient age tier', $result->error());
    }

    public function testVerifyAcceptsHigherTierForLowerMinimum(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'requiredAge' => 18,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '21+');

        $result = $verifier->verify($jwt);

        $this->assertTrue($result->isOk());
    }

    public function testVerifyAccepts16PlusWhenMinimumIs15(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'requiredAge' => 15,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '16+');

        $result = $verifier->verify($jwt);

        $this->assertTrue($result->isOk());
    }

    public function testVerifyAccepts65PlusWhenMinimumIs18(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
            'requiredAge' => 18,
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '65+');

        $result = $verifier->verify($jwt);

        $this->assertTrue($result->isOk());
    }

    public function testVerifyRejectsInvalidCredentialType(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $jwt = $this->makeJwt('did:web:agecheck.me', '18+', ['VerifiableCredential', 'WrongType']);

        $result = $verifier->verify($jwt);

        $this->assertFalse($result->isOk());
        $this->assertSame(ErrorCode::INVALID_CREDENTIAL, $result->code());
        $this->assertSame('Invalid credential type', $result->error());
    }

    public function testVerifyRejectsMalformedJwt(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('x', 32),
        ]);

        $verifier = new Verifier($config, new StaticKeyCache($this->jwks));
        $result = $verifier->verify('not-a-jwt');

        $this->assertFalse($result->isOk());
        $this->assertSame(ErrorCode::INVALID_INPUT, $result->code());
        $this->assertSame('Invalid JWT format', $result->error());
    }

    /**
     * @param array<int,string> $types
     */
    private function makeJwt(string $issuer, string $ageTier, array $types = ['VerifiableCredential', 'AgeTierCredential']): string
    {
        $payload = [
            'iss' => $issuer,
            'sub' => 'did:key:test-subject',
            'nbf' => time() - 10,
            'exp' => time() + 300,
            'vc' => [
                'type' => $types,
                'credentialSubject' => [
                    'id' => 'did:key:test-subject',
                    'ageTier' => $ageTier,
                    'session' => '4b2bc078-8f3f-4b0e-9664-e6c6a89ce5e3',
                ],
            ],
        ];

        return JWT::encode($payload, $this->privatePem, 'ES256', 'k1');
    }

    /**
     * @param array<string,mixed> $details
     * @return array<string,string>
     */
    private function createJwkFromPublicDetails(array $details, string $kid): array
    {
        $ec = isset($details['ec']) && is_array($details['ec']) ? $details['ec'] : null;
        $this->assertIsArray($ec, 'Unable to read EC details for JWK conversion');

        $x = $ec['x'] ?? null;
        $y = $ec['y'] ?? null;
        $this->assertIsString($x, 'Missing EC x coordinate');
        $this->assertIsString($y, 'Missing EC y coordinate');

        return [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $this->base64UrlEncode($x),
            'y' => $this->base64UrlEncode($y),
            'alg' => 'ES256',
            'use' => 'sig',
            'kid' => $kid,
        ];
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
