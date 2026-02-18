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

require __DIR__.'/../vendor/autoload.php';

header('Content-Type: application/json');

/**
 * Emit a JSON response with a stable shape for frontend/server callers.
 *
 * @param array<string,mixed> $body
 */
function jsonResponse(int $statusCode, array $body): void
{
    http_response_code($statusCode);
    echo json_encode($body);
    exit;
}

/**
 * Only allow same-site relative redirects.
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

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(405, [
        'verified' => false,
        'error' => 'Method not allowed',
    ]);
}

$config = new Config([
    'hmacSecret' => 'replace-this-with-at-least-32-random-bytes',
]);
$gate = new Gate($config);

$rawBody = file_get_contents('php://input');
$body = json_decode($rawBody, true);
if (!is_array($body)) {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Invalid JSON body',
    ]);
}

$provider = $body['provider'] ?? 'provider';
if (!is_string($provider) || $provider === '') {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Missing provider',
    ]);
}
if ($provider === 'agecheck') {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Unsupported verification provider',
        'code' => 'unsupported_provider',
    ]);
}

// Expected input shape for this example:
// {
//   "provider": "acme-provider",
//   "redirect": "/",
//   "payload": { "agegateway_session": "<uuid>" },
//   "providerResult": {
//      "verified": true,
//      "ageTier": "18+",
//      "session": "<uuid>",
//      "assurance": "passkey"
//   }
// }
$providerResultRaw = $body['providerResult'] ?? null;
if (!is_array($providerResultRaw)) {
    jsonResponse(400, [
        'verified' => false,
        'error' => 'Missing providerResult',
    ]);
}
$payload = $body['payload'] ?? null;
$payloadSession = null;
if (is_array($payload) && isset($payload['agegateway_session']) && is_string($payload['agegateway_session'])) {
    $payloadSession = $payload['agegateway_session'];
}
$normalized = Provider::normalizeExternalProviderAssertion(
    $providerResultRaw,
    is_string($payloadSession) ? $payloadSession : null
);
if (($normalized['verified'] ?? null) !== true) {
    jsonResponse(401, [
        'verified' => false,
        'error' => (is_string($normalized['message'] ?? null) ? $normalized['message'] : 'Provider verification failed'),
        'code' => (is_string($normalized['code'] ?? null) ? $normalized['code'] : ErrorCode::VERIFY_FAILED),
    ]);
}

Provider::applyProviderAssertionCookie($gate, $normalized);

$redirect = normalizeRedirect($body['redirect'] ?? '/');

jsonResponse(200, [
    'verified' => true,
    'redirect' => $redirect,
    'ageTier' => $normalized['level'],
    'provider' => $provider,
]);
