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

class KeyCache
{
    private string $cacheDir;
    private int $ttl; // seconds
    private int $timeout; // seconds

    public function __construct(
        ?string $cacheDir = null,
        int $ttlSeconds = 86400,
        int $timeoutSeconds = 3
    ) {
        $this->ttl = $ttlSeconds;
        $this->timeout = $timeoutSeconds;

        $dir = $cacheDir ?? sys_get_temp_dir() . '/agecheck';
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new \RuntimeException("Failed to create cache directory: $dir");
            }
        }

        $this->cacheDir = rtrim($dir, '/');
    }

    /**
     * Get cached JWKS or fetch from remote URL.
     *
     * @return array<string,mixed>
     */
    public function getOrFetch(string $url): array
    {
        $cacheFile = $this->cacheFilePath($url);
        $cached = $this->readCacheIfFresh($cacheFile);
        if ($cached !== null) {
            return $cached;
        }

        $json = $this->fetchRemote($url);
        if ($json === null) {
            $stale = $this->readCache($cacheFile);
            if ($stale !== null) {
                return $stale;
            }
            throw new \RuntimeException("Failed to fetch JWKS from $url");
        }

        $jwks = json_decode($json, true);
        if (!is_array($jwks) || !$this->isValidJwks($jwks)) {
            throw new \RuntimeException("Invalid JWKS JSON from $url");
        }

        $encoded = json_encode($jwks);
        if (!is_string($encoded)) {
            throw new \RuntimeException('Failed to encode JWKS cache payload');
        }
        $this->writeAtomic($cacheFile, $encoded);

        return $jwks;
    }

    private function cacheFilePath(string $url): string
    {
        return $this->cacheDir . '/jwks-' . hash('sha256', $url) . '.json';
    }

    private function isFresh(string $cacheFile): bool
    {
        return file_exists($cacheFile)
            && (time() - filemtime($cacheFile)) < $this->ttl;
    }

    /**
     * @param mixed $data
     */
    private function isValidJwks($data): bool
    {
        if (!is_array($data) || !isset($data['keys']) || !is_array($data['keys'])) {
            return false;
        }

        foreach ($data['keys'] as $entry) {
            if (!is_array($entry)) {
                return false;
            }

            $kty = $entry['kty'] ?? null;
            $kid = $entry['kid'] ?? null;
            if (!is_string($kty) || $kty === '' || !is_string($kid) || $kid === '') {
                return false;
            }
        }

        return true;
    }

    private function fetchRemote(string $url): ?string
    {
        if (!$this->isAllowedJwksUrl($url)) {
            return null;
        }
        $ctx = stream_context_create([
            'http' => [
                'timeout' => $this->timeout,
            ],
        ]);
        $json = @file_get_contents($url, false, $ctx);
        if (!$this->isSuccessfulHttpResponse($http_response_header ?? null)) {
            return null;
        }

        return $json === false ? null : $json;
    }

    private function isAllowedJwksUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return false;
        }
        if (($parts['scheme'] ?? null) !== 'https') {
            return false;
        }
        if (!isset($parts['host']) || !is_string($parts['host'])) {
            return false;
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        return true;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function readCacheIfFresh(string $cacheFile): ?array
    {
        if (!$this->isFresh($cacheFile)) {
            return null;
        }

        return $this->readCache($cacheFile);
    }

    /**
     * @return array<string,mixed>|null
     */
    private function readCache(string $cacheFile): ?array
    {
        if (!file_exists($cacheFile)) {
            return null;
        }

        $data = @file_get_contents($cacheFile);
        if ($data === false) {
            return null;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded) || !$this->isValidJwks($decoded)) {
            return null;
        }

        return $decoded;
    }

    /**
     * @param mixed $responseHeader
     */
    private function isSuccessfulHttpResponse($responseHeader): bool
    {
        if (!is_array($responseHeader) || count($responseHeader) === 0) {
            return false;
        }

        $status = $responseHeader[0];
        if (!is_string($status)) {
            return false;
        }

        return preg_match('#^HTTP/\S+\s+2\d\d\b#', $status) === 1;
    }

    private function writeAtomic(string $path, string $payload): void
    {
        $tmpPath = $path . '.tmp.' . bin2hex(random_bytes(8));
        if (@file_put_contents($tmpPath, $payload, LOCK_EX) === false) {
            throw new \RuntimeException("Failed writing JWKS temp cache file: $tmpPath");
        }
        if (!@rename($tmpPath, $path)) {
            @unlink($tmpPath);
            throw new \RuntimeException("Failed to replace JWKS cache file: $path");
        }
    }
}
