# AgeCheck PHP Quickstart

## 1) Install

```sh
composer require agecheck/php
```

Requirements:
- PHP `8.1+`

## 2) Create `config.php`

```php
<?php

declare(strict_types=1);

use AgeCheck\Config;

return new Config([
    'hmacSecret' => 'YOUR_32_BYTE_SECRET',
    'deploymentMode' => Config::DEPLOYMENT_PRODUCTION,
    'allowCustomIssuer' => false,
    'requiredAge' => 18,
    'gatePage' => '/agecheck_gate.php',
    'verifyApi' => '/ageverify_api.php',
    'jwksUrl' => 'https://agecheck.me/.well-known/jwks.json',
]);
```

## 3) Protect a page

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

$config = require __DIR__ . '/config.php';
$gate = new AgeCheck\Gate($config);

$gate->requireVerifiedOrRedirect();

echo '<h1>Welcome! Age Verified.</h1>';
```

The gate is raised when either:

- request contains `X-Age-Gate: true` (production mode)
- deployment mode is `Config::DEPLOYMENT_DEMO` (always gate)

In demo deployment mode, verification accepts both demo and production-issued tokens.

Backend enforcement remains authoritative.

## 4) Create `/agecheck_gate.php`

```php
<?php

declare(strict_types=1);

use AgeCheck\Gate;

require __DIR__ . '/vendor/autoload.php';

$config = require __DIR__ . '/config.php';
$gate = new Gate($config);

$redirect = isset($_GET['redirect']) && is_string($_GET['redirect']) ? $_GET['redirect'] : '/';
$easy = isset($_GET['easy']) && $_GET['easy'] === '1';

echo $gate->renderGatePage([
    'redirect' => $redirect,
    'easyAgeGate' => $easy,
    'easyAgeGateOptions' => [
        'title' => 'Age Restricted Content',
        'subtitle' => 'Please confirm your age anonymously using AgeCheck.me.',
        'verifyButtonText' => 'Verify Now',
    ],
]);
```

Set `easyAgeGate` to `false` (or omit it) to use `agegate.min.js` in custom flow mode.

## 5) Create `/ageverify_api.php`

```php
<?php

declare(strict_types=1);

use AgeCheck\Gate;
use AgeCheck\Verifier;

require __DIR__ . '/vendor/autoload.php';
header('Content-Type: application/json');

$config = require __DIR__ . '/config.php';
$gate = new Gate($config);
$verifier = new Verifier($config);

$body = json_decode(file_get_contents('php://input'), true);
if (!is_array($body) || !isset($body['jwt']) || !is_string($body['jwt'])) {
  http_response_code(400);
  echo json_encode(['verified' => false, 'error' => 'Missing jwt']);
  exit;
}

$result = $verifier->verify($body['jwt']);
if (!$result->isOk()) {
  http_response_code(401);
  echo json_encode(['verified' => false, 'error' => $result->error()]);
  exit;
}

$claims = $result->claims();
$payload = is_array($body['payload'] ?? null) ? $body['payload'] : [];
$payloadSession = isset($payload['agegateway_session']) && is_string($payload['agegateway_session']) ? $payload['agegateway_session'] : null;
$vc = isset($claims['vc']) && is_array($claims['vc']) ? $claims['vc'] : [];
$credentialSubject = isset($vc['credentialSubject']) && is_array($vc['credentialSubject']) ? $vc['credentialSubject'] : [];
$jwtSession = isset($credentialSubject['session']) && is_string($credentialSubject['session']) ? $credentialSubject['session'] : null;
if ($payloadSession === null || $jwtSession === null || $payloadSession !== $jwtSession) {
  http_response_code(401);
  echo json_encode(['verified' => false, 'error' => 'Session binding mismatch']);
  exit;
}

$gate->markVerified($claims);

echo json_encode(['verified' => true, 'redirect' => '/']);
```

## Security notes

- Require session binding on every verification.
- Keep gate policy at edge/CDN with `X-Age-Gate: true`.
- Keep verification on the server.

For additional providers, start from:

- `examples/provider_verify_api.php`

## Multi-provider pattern (AgeCheck + third party)

Use one assertion boundary and one cookie pipeline:

```php
use AgeCheck\Provider;

$provider = $body['provider'] ?? 'agecheck';
$expectedSession = $body['payload']['agegateway_session'] ?? null;
if (!is_string($expectedSession) || $expectedSession === '') {
    // deny
}

if ($provider === 'agecheck') {
    $normalized = Provider::verifyAgeCheckCredential(
        $verifier,
        is_string($body['jwt'] ?? null) ? $body['jwt'] : '',
        $expectedSession
    );
} else {
    $providerResult = $providerClient->verify($body);
    $normalized = Provider::normalizeExternalProviderAssertion($providerResult, $expectedSession);
}

if (($normalized['verified'] ?? null) !== true) {
    // deny
}

Provider::applyProviderAssertionCookie($gate, $normalized);
```
