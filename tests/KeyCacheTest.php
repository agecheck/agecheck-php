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

use AgeCheck\KeyCache;
use PHPUnit\Framework\TestCase;

final class KeyCacheTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cacheDir = sys_get_temp_dir() . '/agecheck-keycache-test-' . bin2hex(random_bytes(8));
        $created = mkdir($this->cacheDir, 0700, true);
        $this->assertTrue($created || is_dir($this->cacheDir));
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        $entries = glob($this->cacheDir . '/*');
        if (is_array($entries)) {
            foreach ($entries as $entry) {
                @unlink($entry);
            }
        }
        @rmdir($this->cacheDir);
    }

    public function testCachesAreIsolatedPerJwksUrl(): void
    {
        $urlA = 'https://issuer-a.example/.well-known/jwks.json';
        $urlB = 'https://issuer-b.example/.well-known/jwks.json';

        $this->writeCacheFile(
            $urlA,
            ['keys' => [['kty' => 'EC', 'kid' => 'kid-a']]],
            time()
        );
        $this->writeCacheFile(
            $urlB,
            ['keys' => [['kty' => 'EC', 'kid' => 'kid-b']]],
            time()
        );

        $cache = new KeyCache($this->cacheDir, 3600, 1);
        $jwksA = $cache->getOrFetch($urlA);
        $jwksB = $cache->getOrFetch($urlB);

        $this->assertSame('kid-a', $jwksA['keys'][0]['kid']);
        $this->assertSame('kid-b', $jwksB['keys'][0]['kid']);
    }

    public function testReturnsStaleCacheWhenFetchFails(): void
    {
        $url = 'http://issuer-invalid.example/.well-known/jwks.json';
        $this->writeCacheFile(
            $url,
            ['keys' => [['kty' => 'EC', 'kid' => 'kid-stale']]],
            time() - 3600
        );

        $cache = new KeyCache($this->cacheDir, 1, 1);
        $jwks = $cache->getOrFetch($url);

        $this->assertSame('kid-stale', $jwks['keys'][0]['kid']);
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function writeCacheFile(string $url, array $payload, int $mtime): void
    {
        $path = $this->cacheDir . '/jwks-' . hash('sha256', $url) . '.json';
        $json = json_encode($payload);
        $this->assertIsString($json);

        $written = file_put_contents($path, $json);
        $this->assertNotFalse($written);

        $touched = touch($path, $mtime);
        $this->assertTrue($touched);
    }
}
