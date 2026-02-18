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

use AgeCheck\VerificationAssertion;
use PHPUnit\Framework\TestCase;

final class VerificationAssertionTest extends TestCase
{
    public function testVerifiedFactoryAcceptsValidValues(): void
    {
        $assertion = VerificationAssertion::verified(
            'agecheck',
            '18+',
            time(),
            'passkey',
            'passkey',
            'webauthn_assertion',
            'txn-1',
            'LOA2'
        );

        $this->assertSame('agecheck', $assertion->provider());
        $this->assertSame('18+', $assertion->level());
        $this->assertSame('passkey', $assertion->assurance());
        $this->assertSame('passkey', $assertion->verificationType());
        $this->assertSame('webauthn_assertion', $assertion->evidenceType());
        $this->assertSame('txn-1', $assertion->providerTransactionId());
        $this->assertSame('LOA2', $assertion->loa());
    }

    public function testFromArrayRequiresVerifiedTrue(): void
    {
        $this->expectException(\RuntimeException::class);
        VerificationAssertion::fromArray([
            'provider' => 'agecheck',
            'verified' => false,
            'level' => '18+',
            'verifiedAtUnix' => time(),
        ]);
    }

    public function testVerifiedFactoryRejectsInvalidLevel(): void
    {
        $this->expectException(\RuntimeException::class);
        VerificationAssertion::verified('agecheck', 'adult', time());
    }
}
