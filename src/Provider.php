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

final class Provider
{
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
    private const AGE_TIER_PATTERN = '/^[1-9]\d*\+$/';
    private const VERIFICATION_TYPES = ['passkey', 'oid4vp', 'other'];
    private const EVIDENCE_TYPES = ['webauthn_assertion', 'sd_jwt', 'zk_attestation', 'other'];

    /**
     * Verify an AgeCheck credential for Existing Gate Integration (Provider Mode).
     *
     * @return array<string,mixed>
     */
    public static function verifyAgeCheckCredential(
        Verifier $verifier,
        string $jwt,
        string $expectedSession,
        string $provider = 'agecheck',
        ?string $assurance = 'passkey'
    ): array {
        if ($jwt === '') {
            return self::failure(ErrorCode::INVALID_INPUT, 'Missing jwt for agecheck provider.');
        }
        if (!self::isUuid($expectedSession)) {
            return self::failure(ErrorCode::INVALID_INPUT, 'expectedSession must be a UUID.');
        }
        if (trim($provider) === '') {
            return self::failure(ErrorCode::INVALID_INPUT, 'provider must be a non-empty string.');
        }

        $result = $verifier->verify($jwt);
        if (!$result->isOk()) {
            return self::failure(
                $result->code() ?? ErrorCode::VERIFY_FAILED,
                'Age validation failed.',
                $result->error()
            );
        }

        $claims = $result->claims();
        if (!is_array($claims)) {
            return self::failure(ErrorCode::VERIFY_FAILED, 'Age validation failed.', 'Missing claims payload.');
        }

        $vc = $claims['vc'] ?? null;
        $credentialSubject = is_array($vc) ? ($vc['credentialSubject'] ?? null) : null;
        $session = is_array($credentialSubject) ? ($credentialSubject['session'] ?? null) : null;
        if (!is_string($session) || !self::isUuid($session)) {
            return self::failure(ErrorCode::SESSION_BINDING_REQUIRED, 'Provider session is required.');
        }
        if (!hash_equals($expectedSession, $session)) {
            return self::failure(ErrorCode::SESSION_BINDING_MISMATCH, 'Session binding mismatch.');
        }

        $ageTier = is_array($credentialSubject) ? ($credentialSubject['ageTier'] ?? null) : null;
        if (!is_string($ageTier) || !self::isAgeTier($ageTier)) {
            return self::failure(ErrorCode::INVALID_AGE_TIER, 'Invalid age tier.');
        }

        $normalized = [
            'provider' => trim($provider),
            'verified' => true,
            'level' => $ageTier,
            'session' => $session,
            'verifiedAtUnix' => time(),
            'verificationType' => 'passkey',
            'evidenceType' => 'webauthn_assertion',
        ];
        if (is_string($assurance) && trim($assurance) !== '') {
            $normalized['assurance'] = trim($assurance);
        }
        $loa = is_array($credentialSubject) ? ($credentialSubject['loa'] ?? null) : null;
        if (is_string($loa) && trim($loa) !== '') {
            $normalized['loa'] = trim($loa);
        }
        $providerTransactionId = $claims['jti'] ?? null;
        if (is_string($providerTransactionId) && trim($providerTransactionId) !== '') {
            $normalized['providerTransactionId'] = trim($providerTransactionId);
        }

        return $normalized;
    }

    /**
     * Normalize external provider verification assertions to one boundary model.
     *
     * @param array<string,mixed> $providerResult
     * @return array<string,mixed>
     */
    public static function normalizeExternalProviderAssertion(array $providerResult, ?string $expectedSession): array
    {
        if ($expectedSession !== null && !self::isUuid($expectedSession)) {
            return self::failure(ErrorCode::INVALID_INPUT, 'expected session must be a UUID.');
        }

        $verified = $providerResult['verified'] ?? null;
        if ($verified !== true) {
            return self::failure(
                self::readString($providerResult, 'code') ?? ErrorCode::VERIFY_FAILED,
                self::readString($providerResult, 'message') ?? 'Provider verification failed.',
                self::readString($providerResult, 'detail')
            );
        }

        $provider = self::readString($providerResult, 'provider');
        if (!is_string($provider) || trim($provider) === '') {
            return self::failure(ErrorCode::INVALID_INPUT, 'provider must be a non-empty string.');
        }

        $level = self::readString($providerResult, 'level');
        if (!is_string($level) || !self::isAgeTier($level)) {
            return self::failure(ErrorCode::INVALID_INPUT, 'provider level must be an age tier like 18+.');
        }

        $session = self::readString($providerResult, 'session');
        if (!is_string($session) || !self::isUuid($session)) {
            return self::failure(ErrorCode::INVALID_INPUT, 'Provider session must be a UUID.');
        }
        if ($expectedSession !== null && !hash_equals($expectedSession, $session)) {
            return self::failure(ErrorCode::SESSION_BINDING_MISMATCH, 'Session binding mismatch.');
        }

        $verifiedAtUnix = time();
        $verifiedAtRaw = $providerResult['verifiedAtUnix'] ?? null;
        if (is_int($verifiedAtRaw) && $verifiedAtRaw > 0) {
            $verifiedAtUnix = $verifiedAtRaw;
        }

        $normalized = [
            'provider' => trim($provider),
            'verified' => true,
            'level' => $level,
            'session' => $session,
            'verifiedAtUnix' => $verifiedAtUnix,
        ];

        $verificationType = self::readString($providerResult, 'verificationType');
        if (is_string($verificationType)) {
            if (!in_array($verificationType, self::VERIFICATION_TYPES, true)) {
                return self::failure(ErrorCode::INVALID_INPUT, 'verificationType is invalid.');
            }
            $normalized['verificationType'] = $verificationType;
        }

        $evidenceType = self::readString($providerResult, 'evidenceType');
        if (is_string($evidenceType)) {
            if (!in_array($evidenceType, self::EVIDENCE_TYPES, true)) {
                return self::failure(ErrorCode::INVALID_INPUT, 'evidenceType is invalid.');
            }
            $normalized['evidenceType'] = $evidenceType;
        }

        $providerTransactionId = self::readString($providerResult, 'providerTransactionId');
        if (is_string($providerTransactionId) && trim($providerTransactionId) !== '') {
            $normalized['providerTransactionId'] = trim($providerTransactionId);
        }

        $loa = self::readString($providerResult, 'loa');
        if (is_string($loa) && trim($loa) !== '') {
            $normalized['loa'] = trim($loa);
        }

        $assurance = self::readString($providerResult, 'assurance');
        if (is_string($assurance) && trim($assurance) !== '') {
            $normalized['assurance'] = trim($assurance);
        }

        return $normalized;
    }

    /**
     * @param array<string,mixed> $assertion
     */
    public static function applyProviderAssertionCookie(Gate $gate, array $assertion): void
    {
        $typed = VerificationAssertion::fromArray($assertion);
        $gate->markVerifiedFromVerificationAssertion($typed);
    }

    /**
     * @return array<string,mixed>
     */
    private static function failure(string $code, string $message, ?string $detail = null): array
    {
        $out = [
            'verified' => false,
            'code' => $code,
            'message' => $message,
        ];
        if (is_string($detail) && $detail !== '') {
            $out['detail'] = $detail;
        }
        return $out;
    }

    /**
     * @param array<string,mixed> $input
     */
    private static function readString(array $input, string $key): ?string
    {
        $value = $input[$key] ?? null;
        if (!is_string($value)) {
            return null;
        }
        return $value;
    }

    private static function isUuid(string $value): bool
    {
        return preg_match(self::UUID_PATTERN, $value) === 1;
    }

    private static function isAgeTier(string $value): bool
    {
        return preg_match(self::AGE_TIER_PATTERN, $value) === 1;
    }
}
