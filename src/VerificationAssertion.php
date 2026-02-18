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

final class VerificationAssertion
{
    private const VERIFICATION_TYPE_PASSKEY = 'passkey';
    private const VERIFICATION_TYPE_OID4VP = 'oid4vp';
    private const VERIFICATION_TYPE_OTHER = 'other';

    private const EVIDENCE_TYPE_WEBAUTHN_ASSERTION = 'webauthn_assertion';
    private const EVIDENCE_TYPE_SD_JWT = 'sd_jwt';
    private const EVIDENCE_TYPE_ZK_ATTESTATION = 'zk_attestation';
    private const EVIDENCE_TYPE_OTHER = 'other';

    private string $provider;
    private string $level;
    private int $verifiedAtUnix;
    private ?string $assurance;
    private ?string $verificationType;
    private ?string $evidenceType;
    private ?string $providerTransactionId;
    private ?string $loa;

    private function __construct(
        string $provider,
        string $level,
        int $verifiedAtUnix,
        ?string $assurance,
        ?string $verificationType,
        ?string $evidenceType,
        ?string $providerTransactionId,
        ?string $loa
    ) {
        $this->provider = $provider;
        $this->level = $level;
        $this->verifiedAtUnix = $verifiedAtUnix;
        $this->assurance = $assurance;
        $this->verificationType = $verificationType;
        $this->evidenceType = $evidenceType;
        $this->providerTransactionId = $providerTransactionId;
        $this->loa = $loa;
    }

    public static function verified(
        string $provider,
        string $level,
        int $verifiedAtUnix,
        ?string $assurance = null,
        ?string $verificationType = null,
        ?string $evidenceType = null,
        ?string $providerTransactionId = null,
        ?string $loa = null
    ): self {
        $providerValue = trim($provider);
        if ($providerValue === '') {
            throw new \RuntimeException('provider must be a non-empty string.');
        }

        if (!preg_match('/^[1-9]\d*\+$/', $level)) {
            throw new \RuntimeException('level must be an age tier like "18+".');
        }

        if ($verifiedAtUnix <= 0) {
            throw new \RuntimeException('verifiedAtUnix must be a positive unix timestamp.');
        }

        $assuranceValue = null;
        if ($assurance !== null) {
            $assuranceTrimmed = trim($assurance);
            if ($assuranceTrimmed !== '') {
                $assuranceValue = $assuranceTrimmed;
            }
        }

        $verificationTypeValue = self::normalizeVerificationType($verificationType);
        $evidenceTypeValue = self::normalizeEvidenceType($evidenceType);
        $providerTransactionIdValue = self::normalizeOptionalString($providerTransactionId);
        $loaValue = self::normalizeOptionalString($loa);

        return new self(
            $providerValue,
            $level,
            $verifiedAtUnix,
            $assuranceValue,
            $verificationTypeValue,
            $evidenceTypeValue,
            $providerTransactionIdValue,
            $loaValue
        );
    }

    /**
     * @param array<string,mixed> $assertion
     */
    public static function fromArray(array $assertion): self
    {
        $provider = $assertion['provider'] ?? null;
        if (!is_string($provider)) {
            throw new \RuntimeException('Missing provider in verification assertion.');
        }

        $verified = $assertion['verified'] ?? null;
        if ($verified !== true) {
            throw new \RuntimeException('Verification assertion must be verified=true.');
        }

        $level = $assertion['level'] ?? null;
        if (!is_string($level)) {
            throw new \RuntimeException('Missing level in verification assertion.');
        }

        $verifiedAtUnixRaw = $assertion['verifiedAtUnix'] ?? null;
        if (!is_int($verifiedAtUnixRaw)) {
            throw new \RuntimeException('Missing verifiedAtUnix in verification assertion.');
        }

        $assurance = $assertion['assurance'] ?? null;
        if ($assurance !== null && !is_string($assurance)) {
            throw new \RuntimeException('assurance must be a string when present.');
        }

        $verificationType = $assertion['verificationType'] ?? null;
        if ($verificationType !== null && !is_string($verificationType)) {
            throw new \RuntimeException('verificationType must be a string when present.');
        }

        $evidenceType = $assertion['evidenceType'] ?? null;
        if ($evidenceType !== null && !is_string($evidenceType)) {
            throw new \RuntimeException('evidenceType must be a string when present.');
        }

        $providerTransactionId = $assertion['providerTransactionId'] ?? null;
        if ($providerTransactionId !== null && !is_string($providerTransactionId)) {
            throw new \RuntimeException('providerTransactionId must be a string when present.');
        }

        $loa = $assertion['loa'] ?? null;
        if ($loa !== null && !is_string($loa)) {
            throw new \RuntimeException('loa must be a string when present.');
        }

        return self::verified(
            $provider,
            $level,
            $verifiedAtUnixRaw,
            $assurance,
            $verificationType,
            $evidenceType,
            $providerTransactionId,
            $loa
        );
    }

    public function provider(): string
    {
        return $this->provider;
    }

    public function level(): string
    {
        return $this->level;
    }

    public function verifiedAtUnix(): int
    {
        return $this->verifiedAtUnix;
    }

    public function assurance(): ?string
    {
        return $this->assurance;
    }

    public function verificationType(): ?string
    {
        return $this->verificationType;
    }

    public function evidenceType(): ?string
    {
        return $this->evidenceType;
    }

    public function providerTransactionId(): ?string
    {
        return $this->providerTransactionId;
    }

    public function loa(): ?string
    {
        return $this->loa;
    }

    private static function normalizeVerificationType(?string $value): ?string
    {
        $normalized = self::normalizeOptionalString($value);
        if ($normalized === null) {
            return null;
        }

        $allowed = [
            self::VERIFICATION_TYPE_PASSKEY,
            self::VERIFICATION_TYPE_OID4VP,
            self::VERIFICATION_TYPE_OTHER,
        ];
        if (!in_array($normalized, $allowed, true)) {
            throw new \RuntimeException('verificationType must be one of: passkey, oid4vp, other.');
        }

        return $normalized;
    }

    private static function normalizeEvidenceType(?string $value): ?string
    {
        $normalized = self::normalizeOptionalString($value);
        if ($normalized === null) {
            return null;
        }

        $allowed = [
            self::EVIDENCE_TYPE_WEBAUTHN_ASSERTION,
            self::EVIDENCE_TYPE_SD_JWT,
            self::EVIDENCE_TYPE_ZK_ATTESTATION,
            self::EVIDENCE_TYPE_OTHER,
        ];
        if (!in_array($normalized, $allowed, true)) {
            throw new \RuntimeException(
                'evidenceType must be one of: webauthn_assertion, sd_jwt, zk_attestation, other.'
            );
        }

        return $normalized;
    }

    private static function normalizeOptionalString(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        $trimmed = trim($value);
        return $trimmed === '' ? null : $trimmed;
    }
}
