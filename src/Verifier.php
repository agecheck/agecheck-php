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

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;

final class Verifier
{
    private KeyCache $keyCache;
    private Config $config;
    private int $leeway; // seconds

    public function __construct(
        Config $config,
        ?KeyCache $keyCache = null,
        int $leewaySeconds = 60
    ) {
        $this->keyCache = $keyCache ?? new KeyCache();
        $this->config = $config;
        $this->leeway = $leewaySeconds;
    }

    /**
     * Verify AgeCheck JWT and enforce VC + age-tier policy.
     */
    public function verify(string $jwt): Result
    {
        try {
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                return Result::failure(ErrorCode::INVALID_INPUT, 'Invalid JWT format');
            }

            [$rawHeader] = $parts;
            $headerJson = $this->base64UrlDecode($rawHeader);
            if ($headerJson === null) {
                return Result::failure(ErrorCode::INVALID_HEADER, 'Invalid JWT header encoding');
            }

            $header = json_decode($headerJson, true);
            if (!is_array($header)) {
                return Result::failure(ErrorCode::INVALID_HEADER, 'Invalid JWT header');
            }

            if (!isset($header['kid']) || !is_string($header['kid']) || $header['kid'] === '') {
                return Result::failure(ErrorCode::INVALID_HEADER, 'Missing or invalid kid');
            }
            if (($header['alg'] ?? null) !== 'ES256') {
                return Result::failure(ErrorCode::INVALID_HEADER, 'Unsupported alg');
            }
            $kid = $header['kid'];

            $parsedKeys = $this->resolveParsedKeys();
            if (!isset($parsedKeys[$kid])) {
                return Result::failure(ErrorCode::UNKNOWN_KEY_ID, 'Unknown key ID');
            }

            $prevLeeway = JWT::$leeway;
            JWT::$leeway = $this->leeway;
            try {
                $decoded = JWT::decode($jwt, $parsedKeys[$kid]);
            } catch (ExpiredException $e) {
                return Result::failure(ErrorCode::TOKEN_EXPIRED, 'Token expired');
            } catch (BeforeValidException $e) {
                return Result::failure(ErrorCode::TOKEN_NOT_YET_VALID, 'Token not valid yet');
            } catch (SignatureInvalidException $e) {
                return Result::failure(ErrorCode::INVALID_SIGNATURE, 'Invalid token signature');
            } finally {
                JWT::$leeway = $prevLeeway;
            }

            try {
                /** @var array<string,mixed> $claims */
                $claims = json_decode(
                    json_encode($decoded, JSON_THROW_ON_ERROR),
                    true,
                    512,
                    JSON_THROW_ON_ERROR
                );
            } catch (\JsonException $e) {
                return Result::failure(ErrorCode::VERIFY_FAILED, 'Verification failed');
            }

            $issuer = isset($claims['iss']) && is_string($claims['iss']) ? $claims['iss'] : null;
            if ($issuer === null || !$this->isAcceptedIssuer($issuer)) {
                return Result::failure(ErrorCode::INVALID_ISSUER, 'Invalid issuer');
            }

            // exp / nbf are enforced by JWT::decode; keep explicit checks for deterministic messages.
            $now = time();
            $exp = $this->readNumericClaim($claims, 'exp');
            if ($exp !== null && $now > $exp + $this->leeway) {
                return Result::failure(ErrorCode::TOKEN_EXPIRED, 'Token expired');
            }
            $nbf = $this->readNumericClaim($claims, 'nbf');
            if ($nbf !== null && $now + $this->leeway < $nbf) {
                return Result::failure(ErrorCode::TOKEN_NOT_YET_VALID, 'Token not valid yet');
            }

            if (!isset($claims['vc']) || !is_array($claims['vc'])) {
                return Result::failure(ErrorCode::INVALID_CREDENTIAL, 'Missing vc object');
            }
            /** @var array<string,mixed> $vc */
            $vc = $claims['vc'];

            $types = $vc['type'] ?? null;
            if (!is_array($types) || !in_array('VerifiableCredential', $types, true) || !in_array('AgeTierCredential', $types, true)) {
                return Result::failure(ErrorCode::INVALID_CREDENTIAL, 'Invalid credential type');
            }

            $subject = $vc['credentialSubject'] ?? null;
            if (!is_array($subject)) {
                return Result::failure(ErrorCode::INVALID_CREDENTIAL, 'Missing credentialSubject');
            }

            $ageTierRaw = $subject['ageTier'] ?? null;
            if (!is_string($ageTierRaw)) {
                return Result::failure(ErrorCode::INVALID_AGE_TIER, 'Missing ageTier');
            }
            $ageTier = $this->parseAgeTier($ageTierRaw);
            if ($ageTier === null) {
                return Result::failure(ErrorCode::INVALID_AGE_TIER, 'Invalid ageTier');
            }
            if ($ageTier < $this->config->requiredAge) {
                return Result::failure(ErrorCode::INSUFFICIENT_AGE_TIER, 'Insufficient age tier');
            }

            return Result::success($claims);
        } catch (\Throwable $e) {
            return Result::failure(ErrorCode::VERIFY_FAILED, 'Verification failed');
        }
    }

    /**
     * @param array<string,mixed> $jwks
     * @return array<string,\Firebase\JWT\Key>
     */
    private function parseKeySet(array $jwks): array
    {
        try {
            return JWK::parseKeySet($jwks);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Invalid JWKS key set', 0, $e);
        }
    }

    private function isAcceptedIssuer(string $issuer): bool
    {
        foreach ($this->config->expectedIssuers() as $candidate) {
            if (hash_equals($candidate, $issuer)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return array<string,\Firebase\JWT\Key>
     */
    private function resolveParsedKeys(): array
    {
        $all = [];
        $lastError = null;

        foreach ($this->config->jwksUrls() as $jwksUrl) {
            try {
                $jwks = $this->keyCache->getOrFetch($jwksUrl);
                $parsed = $this->parseKeySet($jwks);
                foreach ($parsed as $kid => $key) {
                    $all[$kid] = $key;
                }
            } catch (\Throwable $error) {
                $lastError = $error;
            }
        }

        if (count($all) === 0) {
            if ($lastError instanceof \Throwable) {
                throw new \RuntimeException('Unable to resolve JWKS keys.', 0, $lastError);
            }
            throw new \RuntimeException('Unable to resolve JWKS keys.');
        }

        return $all;
    }

    private function parseAgeTier(string $ageTier): ?int
    {
        if (!preg_match('/^[1-9]\d*\+$/', $ageTier)) {
            return null;
        }
        $value = (int) substr($ageTier, 0, -1);
        if ($value < 1) {
            return null;
        }
        return $value;
    }

    /**
     * Safe base64url decode. Returns null on failure.
     */
    private function base64UrlDecode(string $input): ?string
    {
        $b64 = strtr($input, '-_', '+/');
        $padLen = (4 - strlen($b64) % 4) % 4;
        if ($padLen) {
            $b64 .= str_repeat('=', $padLen);
        }
        $decoded = base64_decode($b64, true);
        return $decoded === false ? null : $decoded;
    }

    /**
     * @param array<string,mixed> $claims
     */
    private function readNumericClaim(array $claims, string $name): ?int
    {
        if (!isset($claims[$name])) {
            return null;
        }

        $value = $claims[$name];
        if (is_int($value)) {
            return $value;
        }
        if (is_float($value)) {
            return (int) $value;
        }

        return null;
    }
}
