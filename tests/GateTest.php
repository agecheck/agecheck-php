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
use AgeCheck\Gate;
use PHPUnit\Framework\TestCase;

final class GateTest extends TestCase
{
    public function testGateNotRequiredWithoutHeaderInProductionMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
            'deploymentMode' => Config::DEPLOYMENT_PRODUCTION,
        ]);

        $gate = new Gate($config);

        $this->assertFalse($gate->isGateRequired([]));
    }

    public function testGateRequiredWhenHeaderTrueInProductionMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
            'deploymentMode' => Config::DEPLOYMENT_PRODUCTION,
        ]);

        $gate = new Gate($config);

        $this->assertTrue($gate->isGateRequired(['HTTP_X_AGE_GATE' => 'true']));
        $this->assertTrue($gate->isGateRequired(['HTTP_X_AGE_GATE' => 'TRUE']));
    }

    public function testGateAlwaysRequiredInDemoDeploymentMode(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
            'deploymentMode' => Config::DEPLOYMENT_DEMO,
        ]);

        $gate = new Gate($config);

        $this->assertTrue($gate->isGateRequired([]));
        $this->assertTrue($gate->isGateRequired(['HTTP_X_AGE_GATE' => 'false']));
    }

    public function testIsVerifiedAcceptsValidSignedCookie(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);
        $gate = new Gate($config);

        $payload = json_encode([
            'verified' => true,
            'exp' => time() + 300,
            'level' => '18+',
        ]);
        $this->assertIsString($payload);

        $sig = hash_hmac('sha256', $payload, $config->hmacSecret);
        $cookieValue = base64_encode($payload) . '.' . $sig;

        $this->assertTrue($gate->isVerified([$config->cookieName => $cookieValue]));
    }

    public function testIsVerifiedRejectsTamperedCookie(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);
        $gate = new Gate($config);

        $payload = json_encode([
            'verified' => true,
            'exp' => time() + 300,
            'level' => '18+',
        ]);
        $this->assertIsString($payload);

        $sig = hash_hmac('sha256', $payload, $config->hmacSecret);
        $cookieValue = base64_encode($payload) . '.' . $sig . 'tamper';

        $this->assertFalse($gate->isVerified([$config->cookieName => $cookieValue]));
    }

    public function testIsVerifiedRejectsExpiredCookie(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);
        $gate = new Gate($config);

        $payload = json_encode([
            'verified' => true,
            'exp' => time() - 1,
            'level' => '18+',
        ]);
        $this->assertIsString($payload);

        $sig = hash_hmac('sha256', $payload, $config->hmacSecret);
        $cookieValue = base64_encode($payload) . '.' . $sig;

        $this->assertFalse($gate->isVerified([$config->cookieName => $cookieValue]));
    }

    public function testRenderGatePageUsesEasyAgeGateScriptWhenEnabled(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
            'verifyApi' => '/ageverify_api.php',
        ]);

        $gate = new Gate($config);
        $html = $gate->renderGatePage([
            'easyAgeGate' => true,
            'easyAgeGateOptions' => [
                'title' => 'Age Restricted Content',
            ],
        ]);

        $this->assertStringContainsString('easy-agegate.min.js', $html);
        $this->assertStringContainsString('window.AgeCheck.AgeGate.init', $html);
        $this->assertStringNotContainsString('<script src="https://cdn.agecheck.me/agegate/v1/agegate.min.js"></script>', $html);
    }

    public function testRenderGatePageUsesCoreAgeGateScriptByDefault(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);

        $gate = new Gate($config);
        $html = $gate->renderGatePage();

        $this->assertStringContainsString('agegate.min.js', $html);
        $this->assertStringContainsString('window.AgeCheck.launchAgeGate', $html);
        $this->assertStringContainsString('"session"', $html);
    }

    public function testRenderGatePageNormalizesVerifyApiToRelativePath(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);

        $gate = new Gate($config);
        $html = $gate->renderGatePage([
            'verifyApi' => 'https://example.com/verify',
        ]);

        $this->assertStringContainsString('const verifyApi =', $html);
        $this->assertStringNotContainsString('example.com', $html);
    }

    public function testRenderGatePageFallsBackToDefaultScriptWhenScriptUrlIsInvalid(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);

        $gate = new Gate($config);
        $html = $gate->renderGatePage([
            'agegateCdnUrl' => 'javascript:alert(1)',
            'easyAgeGateCdnUrl' => 'http://cdn.example.com/easy-agegate.min.js',
        ]);

        $this->assertStringContainsString('https://cdn.agecheck.me/agegate/v1/agegate.min.js', $html);
        $this->assertStringNotContainsString('javascript:alert(1)', $html);
        $this->assertStringNotContainsString('http://cdn.example.com/easy-agegate.min.js', $html);
    }

    public function testRenderGatePageUsesProvidedHttpsScriptUrl(): void
    {
        $config = new Config([
            'hmacSecret' => str_repeat('s', 32),
        ]);

        $gate = new Gate($config);
        $html = $gate->renderGatePage([
            'agegateCdnUrl' => 'https://cdn.example.com/agegate.min.js',
        ]);

        $this->assertStringContainsString('https://cdn.example.com/agegate.min.js', $html);
    }
}
