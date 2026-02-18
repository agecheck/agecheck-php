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

use AgeCheck\ErrorCode;
use AgeCheck\Provider;
use PHPUnit\Framework\TestCase;

final class ProviderTest extends TestCase
{
    public function testNormalizeExternalProviderAssertionAcceptsValidInput(): void
    {
        $expectedSession = '123e4567-e89b-42d3-a456-426614174000';
        $normalized = Provider::normalizeExternalProviderAssertion([
            'verified' => true,
            'provider' => 'provider-x',
            'level' => '21+',
            'session' => $expectedSession,
            'verifiedAtUnix' => 1000,
            'assurance' => 'passkey',
            'verificationType' => 'oid4vp',
            'evidenceType' => 'sd_jwt',
            'providerTransactionId' => 'txn-2',
            'loa' => 'LOA3',
        ], $expectedSession);

        $this->assertTrue($normalized['verified']);
        $this->assertSame('provider-x', $normalized['provider']);
        $this->assertSame('21+', $normalized['level']);
        $this->assertSame($expectedSession, $normalized['session']);
        $this->assertSame(1000, $normalized['verifiedAtUnix']);
        $this->assertSame('oid4vp', $normalized['verificationType']);
        $this->assertSame('sd_jwt', $normalized['evidenceType']);
        $this->assertSame('txn-2', $normalized['providerTransactionId']);
        $this->assertSame('LOA3', $normalized['loa']);
    }

    public function testNormalizeExternalProviderAssertionRejectsSessionMismatch(): void
    {
        $normalized = Provider::normalizeExternalProviderAssertion([
            'verified' => true,
            'provider' => 'provider-x',
            'level' => '21+',
            'session' => '123e4567-e89b-42d3-a456-426614174001',
        ], '123e4567-e89b-42d3-a456-426614174002');

        $this->assertFalse($normalized['verified']);
        $this->assertSame(ErrorCode::SESSION_BINDING_MISMATCH, $normalized['code']);
    }

    public function testNormalizeExternalProviderAssertionRejectsInvalidProviderSession(): void
    {
        $normalized = Provider::normalizeExternalProviderAssertion([
            'verified' => true,
            'provider' => 'provider-x',
            'level' => '21+',
            'session' => 'not-a-uuid',
        ], '123e4567-e89b-42d3-a456-426614174003');

        $this->assertFalse($normalized['verified']);
        $this->assertSame(ErrorCode::INVALID_INPUT, $normalized['code']);
    }
}
