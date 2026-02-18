# AgeCheck PHP SDK (`agecheck/php`)

[![CI](https://github.com/agecheck/agecheck-php/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agecheck/agecheck-php/actions/workflows/ci.yml)
[![Compatibility](https://img.shields.io/github/actions/workflow/status/agecheck/agecheck-php/compatibility.yml?branch=main&label=Compatibility)](https://github.com/agecheck/agecheck-php/actions/workflows/compatibility.yml)
[![Packagist](https://img.shields.io/packagist/v/agecheck/php)](https://packagist.org/packages/agecheck/php)

Server-side SDK for AgeCheck gate policy and JWT verification.

## Features

- Verify AgeCheck JWTs signed with ES256
- Deployment mode: production or demo
- Enforce minimum age tier (`N+`, not capped at `21+`)
- Require session binding (`vc.credentialSubject.session`)
- Raise gate from edge header (`X-Age-Gate: true`) in production, or always gate in demo deployment mode
- Create and verify signed verification cookies
- Resolve verification keys from deployment-mode JWKS (`agecheck.me` for production, `demo.agecheck.me` for demo)
- Cache JWKS with TTL and stale-cache fallback

## Install

```bash
composer require agecheck/php
```

Requirements:
- PHP `8.1+`

## Core usage

```php
<?php

declare(strict_types=1);

use AgeCheck\Config;
use AgeCheck\Gate;
use AgeCheck\Verifier;

$config = new Config([
    'hmacSecret' => 'YOUR_32_BYTE_SECRET',
    'deploymentMode' => Config::DEPLOYMENT_PRODUCTION, // production | demo
    'requiredAge' => 18,
    'cookieTtl' => 86400, // seconds; hostmaster-controlled (e.g. 31536000 for 1 year)
    // Defaults are pinned to AgeCheck issuer/JWKS unless explicitly opted in.
    'allowCustomIssuer' => false,
    'gateHeaderName' => 'X-Age-Gate',
    'gateHeaderRequiredValue' => 'true',
]);

$gate = new Gate($config);
$verifier = new Verifier($config);

if ($gate->isGateRequired()) {
    $result = $verifier->verify($jwt);

    if (!$result->isOk()) {
        // deny
    }
}
```

## Easy AgeGate Option

You can render gate HTML with either:

- `easyAgeGate: true` using `easy-agegate.min.js`, or
- `easyAgeGate: false` using plain `agegate.min.js` (full custom UI flow)

```php
<?php

declare(strict_types=1);

use AgeCheck\Gate;

$gate = new Gate($config);

echo $gate->renderGatePage([
    'redirect' => '/protected',
    'easyAgeGate' => true,
    'easyAgeGateOptions' => [
        'title' => 'Age Restricted Content',
        'subtitle' => 'Please confirm your age anonymously using AgeCheck.me.',
        'verifyButtonText' => 'Verify Now',
        'logoUrl' => 'https://your-cdn/logo.svg', // optional
    ],
]);
```

## Cookie helpers

```php
<?php

declare(strict_types=1);

use AgeCheck\Gate;

$gate = new Gate($config);

if ($result->isOk() && is_array($result->claims())) {
    $gate->markVerified($result->claims());
}
```

Use `Gate::isVerified()` on protected routes to validate the signed cookie.

Signed cookie payload is minimal and stateless:

```json
{ "verified": true, "exp": 1700000000, "level": "18+" }
```

You can also set the cookie through a provider-agnostic assertion boundary:

```php
use AgeCheck\VerificationAssertion;

$assertion = VerificationAssertion::verified('agecheck', '18+', time(), 'passkey');
$gate->markVerifiedFromVerificationAssertion($assertion);
```

## Provider integration

Hostmasters can run multiple providers side-by-side and still keep one cookie/session contract, matching the Node SDK provider-agnostic pattern.

```php
use AgeCheck\Provider;

$expectedSession = $body['payload']['agegateway_session'] ?? null;
if (!is_string($expectedSession) || $expectedSession === '') {
    // deny
}

if (($body['provider'] ?? 'agecheck') === 'agecheck') {
    $normalized = Provider::verifyAgeCheckCredential($verifier, $body['jwt'] ?? '', $expectedSession);
} else {
    $external = $providerService->verify($body);
    $normalized = Provider::normalizeExternalProviderAssertion($external, $expectedSession);
}

if (($normalized['verified'] ?? null) !== true) {
    // deny (see $normalized['code'])
}

Provider::applyProviderAssertionCookie($gate, $normalized);
```

All providers converge to one assertion boundary (`provider`, `verified`, `level`, `session`, `verifiedAtUnix`), which keeps cookie issuance and protected-route enforcement consistent.

Session rules:
- `payload.agegateway_session` is required
- session must be a UUID
- provider assertion `session` must match `payload.agegateway_session`

Provider metadata fields (optional):
- `verificationType`: `passkey | oid4vp | other`
- `evidenceType`: `webauthn_assertion | sd_jwt | zk_attestation | other`
- `providerTransactionId`: provider transaction/reference id
- `loa`: level of assurance string

## Security notes

- Backend enforcement remains authoritative; browser callbacks alone are not trusted.
- Require session binding in verification (`payload.agegateway_session` must equal `vc.credentialSubject.session`).
- Use edge policy to set `X-Age-Gate: true` where gate is legally required.
- Use HTTPS JWKS only. Defaults are mode-specific:
  - production: `https://agecheck.me/.well-known/jwks.json`
  - demo: `https://demo.agecheck.me/.well-known/jwks.json` with production JWKS fallback for mixed demo/prod acceptance
- Custom issuer/JWKS overrides are disabled by default. Enable with `allowCustomIssuer=true` only when intentional.

## Standardized error codes

Verifier and provider helpers emit stable error codes such as:

- `invalid_input`
- `invalid_issuer`
- `invalid_credential`
- `invalid_age_tier`
- `insufficient_age_tier`
- `session_binding_required`
- `session_binding_mismatch`
- `token_expired`
- `token_not_yet_valid`
- `invalid_signature`
- `unknown_key_id`
- `verify_failed`

## Examples

See `examples/`:

- `examples/protected_index.php`
- `examples/agecheck_gate.php`
- `examples/ageverify_api.php`
- `examples/provider_verify_api.php`
- `examples/session_api.php`
- `examples/session_reset_api.php`

`examples/protected_index.php` mirrors the Node reference behavior:
- server-side gate enforcement
- restricted page rendering only after cookie validation
- signed-cookie TTL countdown and reset action

## License

Apache-2.0
