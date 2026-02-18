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

use AgeCheck\Config;
use AgeCheck\ErrorCode;
use AgeCheck\Gate;
use AgeCheck\Provider;
use AgeCheck\Verifier;

require __DIR__.'/../vendor/autoload.php';

header("Content-Type: application/json");

/**
 * Emit a JSON response with a stable shape for the frontend contract.
 */
function jsonResponse(int $statusCode, array $body): void
{
    http_response_code($statusCode);
    echo json_encode($body);
    exit;
}

/**
 * Only allow same-site relative paths to prevent open redirects.
 */
function normalizeRedirect($redirect): string
{
    if (!is_string($redirect) || $redirect === '') {
        return '/';
    }

    $parts = parse_url($redirect);
    if ($parts === false) {
        return '/';
    }

    if (isset($parts['scheme']) || isset($parts['host'])) {
        return '/';
    }

    $path = $parts['path'] ?? '/';
    if (!is_string($path) || $path === '' || $path[0] !== '/') {
        $path = '/';
    }

    $query = '';
    if (isset($parts['query']) && is_string($parts['query']) && $parts['query'] !== '') {
        $query = '?' . $parts['query'];
    }

    return $path . $query;
}

// 1. Load config
$config = new Config([
    'hmacSecret' => 'replace-this-with-at-least-32-random-bytes', // REQUIRED
    // 'cookieTtl' => 86400,               // optional override
    // 'gatePage' => '/agecheck_gate.php', // optional override
]);

// 2. Instances
$gate      = new Gate($config);
$verifier  = new Verifier($config);

// 3. Get request body
$rawBody = file_get_contents("php://input");
$body = json_decode($rawBody, true);
if (!is_array($body)) {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Invalid JSON body',
    ]);
}

$jwt = $body['jwt'] ?? null;
$payload = $body['payload'] ?? null;
$redirect = normalizeRedirect($body['redirect'] ?? '/');
$provider = $body['provider'] ?? 'agecheck';

// 4. Validate required input
if (!is_string($jwt) || $jwt === '') {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Missing jwt',
    ]);
}

if (!is_string($provider) || $provider === '') {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Missing provider',
    ]);
}

if ($provider !== 'agecheck') {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Unsupported verification provider',
        'code' => 'unsupported_provider',
    ]);
}

// 5. Verify JWT cryptographically
$payloadSession = null;
if (is_array($payload) && isset($payload['agegateway_session']) && is_string($payload['agegateway_session'])) {
    $payloadSession = $payload['agegateway_session'];
}
if (!is_string($payloadSession) || $payloadSession === '') {
    jsonResponse(401, [
        'verified' => false,
        'error' => 'Missing required session binding.',
        'code' => ErrorCode::SESSION_BINDING_REQUIRED,
    ]);
}

// 6. Verify and normalize into provider assertion.
$normalized = Provider::verifyAgeCheckCredential($verifier, $jwt, $payloadSession, 'agecheck', 'passkey');
if (($normalized['verified'] ?? null) !== true) {
    jsonResponse(401, [
        'verified' => false,
        'error' => (is_string($normalized['message'] ?? null) ? $normalized['message'] : 'Age validation failed.'),
        'code' => (is_string($normalized['code'] ?? null) ? $normalized['code'] : ErrorCode::VERIFY_FAILED),
        'detail' => (is_string($normalized['detail'] ?? null) ? $normalized['detail'] : null),
    ]);
}

// 7. Mark user as verified (set signed cookie) through provider-agnostic assertion.
Provider::applyProviderAssertionCookie($gate, $normalized);

// 8. Respond success + redirect
jsonResponse(200, [
    'verified' => true,
    'redirect' => $redirect,
    'ageTier' => $normalized['level'],
    'provider' => 'agecheck',
]);
