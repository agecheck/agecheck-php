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

final class Gate
{
    private const DEFAULT_AGEGATE_CDN_URL = 'https://cdn.agecheck.me/agegate/v1/agegate.min.js';
    private const DEFAULT_EASY_AGEGATE_CDN_URL = 'https://cdn.agecheck.me/agegate/v1/easy-agegate.min.js';
    /** @var array<int,string> */
    private const DEFAULT_INCLUDE_FIELDS = ['session', 'pidProvider', 'verificationMethod', 'loa'];

    private Config $cfg;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
    }

    /**
     * Gate is raised when:
     * - deploymentMode is demo, or
     * - inbound request carries configured edge header with expected value.
     */
    public function isGateRequired(?array $server = null): bool
    {
        if ($this->cfg->deploymentMode === Config::DEPLOYMENT_DEMO) {
            return true;
        }

        $serverData = $server ?? $_SERVER;
        $headerValue = $this->readHeader($serverData, $this->cfg->gateHeaderName);
        if ($headerValue === null) {
            return false;
        }

        return strtolower(trim($headerValue)) === strtolower($this->cfg->gateHeaderRequiredValue);
    }

    /**
     * Returns true if user is verified according to the server-trusted cookie.
     */
    public function isVerified(?array $cookies = null): bool
    {
        return $this->verifiedCookiePayload($cookies) !== null;
    }

    /**
     * Returns validated verification payload or null when invalid/missing.
     *
     * @param array<string,mixed>|null $cookies
     * @return array{verified:true,exp:int,level:string}|null
     */
    public function verifiedCookiePayload(?array $cookies = null): ?array
    {
        $cookieBag = $cookies ?? $_COOKIE;
        $name = $this->cfg->cookieName;

        if (!isset($cookieBag[$name]) || !is_string($cookieBag[$name])) {
            return null;
        }

        [$b64, $sig] = array_pad(explode('.', $cookieBag[$name], 2), 2, null);
        if (!is_string($b64) || $b64 === '' || !is_string($sig) || $sig === '') {
            return null;
        }

        $data = base64_decode($b64, true);
        if ($data === false) {
            return null;
        }

        $expectedSig = hash_hmac('sha256', $data, $this->cfg->hmacSecret);
        if (!hash_equals($expectedSig, $sig)) {
            return null; // Cookie tampered with
        }

        $payload = json_decode($data, true);
        if (!is_array($payload)) {
            return null;
        }

        if (!isset($payload['verified']) || $payload['verified'] !== true) {
            return null;
        }

        if (!isset($payload['exp']) || !is_int($payload['exp']) || $payload['exp'] < time()) {
            return null;
        }

        if (!isset($payload['level']) || !is_string($payload['level']) || $payload['level'] === '') {
            return null;
        }

        return [
            'verified' => true,
            'exp' => $payload['exp'],
            'level' => $payload['level'],
        ];
    }

    /**
     * If gate is required and user is not verified, redirect to gatePage with ?redirect=.
     */
    public function requireVerifiedOrRedirect(): void
    {
        if (!$this->isGateRequired()) {
            return;
        }
        if ($this->isVerified()) {
            return;
        }

        $redirectSource = '/';
        if (isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI']) && $_SERVER['REQUEST_URI'] !== '') {
            $redirectSource = $_SERVER['REQUEST_URI'];
        }

        $redirect = rawurlencode($redirectSource);
        header("Location: {$this->cfg->gatePage}?redirect={$redirect}");
        exit;
    }

    /**
     * Mark user as verified after successful JWT validation.
     *
     * @param array<string,mixed> $claims
     */
    public function markVerified(array $claims): void
    {
        $this->markVerifiedFromVerificationAssertion(
            VerificationAssertion::verified(
                'agecheck',
                $this->extractAgeTier($claims),
                time(),
                'passkey',
                'passkey',
                'webauthn_assertion',
                $this->extractProviderTransactionId($claims),
                $this->extractLoa($claims)
            )
        );
    }

    /**
     * Provider-agnostic verification assertion for multi-provider integrations.
     *
     * Expected shape:
     * - provider: non-empty string
     * - verified: true
     * - level: age tier string like "18+"
     * - verifiedAtUnix: unix timestamp
     *
     * @param array<string,mixed> $assertion
     */
    public function markVerifiedFromAssertion(array $assertion): void
    {
        $typedAssertion = VerificationAssertion::fromArray($assertion);
        $this->markVerifiedFromVerificationAssertion($typedAssertion);
    }

    public function markVerifiedFromVerificationAssertion(VerificationAssertion $assertion): void
    {
        $level = $assertion->level();

        $expiry = time() + $this->cfg->cookieTtl;
        $payload = [
            'verified' => true,
            'exp' => $expiry,
            'level' => $level,
        ];

        $json = json_encode($payload);
        if (!is_string($json)) {
            throw new \RuntimeException('Failed to encode verification cookie payload.');
        }
        $sig = hash_hmac('sha256', $json, $this->cfg->hmacSecret);
        $cookieValue = base64_encode($json) . '.' . $sig;

        $this->emitSetCookie($cookieValue, $this->cfg->cookieTtl, $expiry);
    }

    public function clear(): void
    {
        $this->emitSetCookie('', 0, time() - 3600);
    }

    /**
     * @param array<string,mixed> $claims
     */
    private function extractAgeTier(array $claims): string
    {
        if (!isset($claims['vc']) || !is_array($claims['vc'])) {
            throw new \RuntimeException('Missing vc object in claims.');
        }
        $subject = $claims['vc']['credentialSubject'] ?? null;
        if (!is_array($subject)) {
            throw new \RuntimeException('Missing credentialSubject in claims.');
        }
        $ageTier = $subject['ageTier'] ?? null;
        if (!is_string($ageTier) || $ageTier === '') {
            throw new \RuntimeException('Missing ageTier in claims.');
        }
        return $ageTier;
    }

    /**
     * @param array<string,mixed> $claims
     */
    private function extractProviderTransactionId(array $claims): ?string
    {
        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '') {
            return null;
        }
        return $jti;
    }

    /**
     * @param array<string,mixed> $claims
     */
    private function extractLoa(array $claims): ?string
    {
        if (!isset($claims['vc']) || !is_array($claims['vc'])) {
            return null;
        }
        $subject = $claims['vc']['credentialSubject'] ?? null;
        if (!is_array($subject)) {
            return null;
        }
        $loa = $subject['loa'] ?? null;
        if (!is_string($loa) || $loa === '') {
            return null;
        }
        return $loa;
    }

    private function emitSetCookie(string $value, int $maxAge, int $expiresAtUnix): void
    {
        $expires = gmdate('D, d M Y H:i:s', $expiresAtUnix) . ' GMT';
        $headerValue = sprintf(
            '%s=%s; Path=/; Max-Age=%d; Expires=%s; HttpOnly; Secure; SameSite=Lax',
            $this->cfg->cookieName,
            $value,
            $maxAge,
            $expires
        );
        header('Set-Cookie: ' . $headerValue, false);
    }

    /**
     * Render a gate page that launches AgeCheck and posts JWT to verify API.
     *
     * Supported options:
     * - redirect: string
     * - verifyApi: string
     * - easyAgeGate: bool
     * - agegateCdnUrl: string
     * - easyAgeGateCdnUrl: string
     * - includeFields: array<int,string>
     * - easyAgeGateOptions: array<string,mixed>
     *
     * @param array<string,mixed> $options
     */
    public function renderGatePage(array $options = []): string
    {
        $redirect = $this->normalizeRedirect($this->readStringOption($options, 'redirect') ?? '/');
        $verifyApi = $this->normalizeRelativePath(
            $this->readStringOption($options, 'verifyApi') ?? $this->cfg->verifyApi
        );
        $easyAgeGate = $this->readBoolOption($options, 'easyAgeGate') ?? false;
        $agegateCdnUrl = $this->normalizeScriptUrl(
            $this->readStringOption($options, 'agegateCdnUrl'),
            self::DEFAULT_AGEGATE_CDN_URL
        );
        $easyCdnUrl = $this->normalizeScriptUrl(
            $this->readStringOption($options, 'easyAgeGateCdnUrl'),
            self::DEFAULT_EASY_AGEGATE_CDN_URL
        );
        $includeFields = $this->normalizeIncludeFields($options['includeFields'] ?? null);

        if ($easyAgeGate) {
            $easyOptions = is_array($options['easyAgeGateOptions'] ?? null) ? $options['easyAgeGateOptions'] : [];
            $easyOptions['include'] = $includeFields;
            return $this->renderEasyGatePage($redirect, $verifyApi, $easyCdnUrl, $easyOptions);
        }

        return $this->renderCustomGatePage($redirect, $verifyApi, $agegateCdnUrl, $includeFields);
    }

    private function readHeader(array $server, string $headerName): ?string
    {
        $normalized = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
        if (isset($server[$normalized]) && is_string($server[$normalized])) {
            return $server[$normalized];
        }
        if (isset($server[$headerName]) && is_string($server[$headerName])) {
            return $server[$headerName];
        }
        return null;
    }

    /**
     * @param mixed $value
     * @return array<int,string>
     */
    private function normalizeIncludeFields($value): array
    {
        if (!is_array($value)) {
            return self::DEFAULT_INCLUDE_FIELDS;
        }

        $allowed = array_flip(self::DEFAULT_INCLUDE_FIELDS);
        $selected = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                continue;
            }
            if (!isset($allowed[$item])) {
                continue;
            }
            $selected[$item] = true;
        }

        // Session binding is required and therefore always included.
        $selected['session'] = true;

        $ordered = [];
        foreach (self::DEFAULT_INCLUDE_FIELDS as $field) {
            if (isset($selected[$field])) {
                $ordered[] = $field;
            }
        }
        return $ordered;
    }

    private function normalizeRedirect(string $raw): string
    {
        if ($raw === '') {
            return '/';
        }

        $parts = parse_url($raw);
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

    private function normalizeRelativePath(string $raw): string
    {
        if ($raw === '') {
            return '/';
        }

        $parts = parse_url($raw);
        if ($parts === false || isset($parts['scheme']) || isset($parts['host'])) {
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

    private function normalizeScriptUrl(?string $raw, string $default): string
    {
        $candidate = is_string($raw) ? trim($raw) : '';
        if ($candidate === '') {
            return $default;
        }

        $parts = parse_url($candidate);
        if ($parts === false) {
            return $default;
        }
        if (($parts['scheme'] ?? null) !== 'https') {
            return $default;
        }
        if (!isset($parts['host']) || !is_string($parts['host']) || $parts['host'] === '') {
            return $default;
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            return $default;
        }

        return $candidate;
    }

    /**
     * @param array<string,mixed> $options
     */
    private function readStringOption(array $options, string $name): ?string
    {
        if (!array_key_exists($name, $options)) {
            return null;
        }
        return is_string($options[$name]) ? $options[$name] : null;
    }

    /**
     * @param array<string,mixed> $options
     */
    private function readBoolOption(array $options, string $name): ?bool
    {
        if (!array_key_exists($name, $options)) {
            return null;
        }
        return is_bool($options[$name]) ? $options[$name] : null;
    }

    /**
     * @param array<int,string> $includeFields
     */
    private function renderCustomGatePage(string $redirect, string $verifyApi, string $agegateCdnUrl, array $includeFields): string
    {
        $agegateScriptSrc = htmlspecialchars($agegateCdnUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $redirectJson = $this->safeJsonEncode($redirect);
        $verifyApiJson = $this->safeJsonEncode($verifyApi);
        $includeJson = $this->safeJsonEncode($includeFields);

        return <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>AgeCheck Gate</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;min-height:100vh;background:radial-gradient(circle at 20% 0%, #1e1b4b 0%, #0b0d14 48%, #090b11 100%);color:#e5e7eb}
    .overlay{position:fixed;inset:0;display:grid;place-items:center;padding:1rem;background:rgba(5,8,16,.82);backdrop-filter:blur(12px) saturate(.9)}
    .modal{width:min(520px,100%);border-radius:1rem;border:1px solid rgba(255,255,255,.16);background:linear-gradient(180deg,rgba(12,16,30,.95),rgba(9,12,22,.97));padding:clamp(1rem,4vw,1.5rem)}
    .kicker{margin:0;color:#fbbf24;font-size:.75rem;letter-spacing:.08em;text-transform:uppercase}
    h2{margin:.5rem 0 0;font-size:clamp(1.2rem,4vw,1.6rem)}
    p{margin:.7rem 0 0;color:#cbd5e1}
    .actions{display:grid;gap:.65rem;margin-top:1rem}
    button{width:100%;padding:12px;border:0;border-radius:10px;background:#7c3aed;color:white;font-weight:700;cursor:pointer}
    #status{margin-top:12px;font-size:14px;color:#94a3b8}
  </style>
</head>
<body>
  <section class="overlay">
    <div class="modal">
      <p class="kicker">Age Restricted Content</p>
      <h2>Anonymous Age Confirmation Required</h2>
      <p>Please confirm your age anonymously using AgeCheck.me.</p>
      <div class="actions">
        <button id="verify">Verify Now</button>
      </div>
      <p id="status"></p>
    </div>
  </section>
  <script src="{$agegateScriptSrc}"></script>
  <script>
    const status = document.getElementById('status');
    const redirect = {$redirectJson};
    const verifyApi = {$verifyApiJson};
    const includeFields = {$includeJson};

    document.getElementById('verify').addEventListener('click', () => {
      const session = crypto.randomUUID();
      status.textContent = 'Opening secure verification...';
      window.AgeCheck.launchAgeGate({
        session,
        include: includeFields,
        onSuccess: async (jwt, payload) => {
          const res = await fetch(verifyApi, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jwt, payload, redirect })
          });
          const out = await res.json();
          if (out.verified && typeof out.redirect === 'string') {
            window.location.assign(out.redirect);
            return;
          }
          status.textContent = out.error || 'Verification failed.';
        },
        onFailure: (err) => {
          status.textContent = (err && err.message) ? err.message : 'Verification failed.';
        }
      });
    });
  </script>
</body>
</html>
HTML;
    }

    /**
     * @param array<string,mixed> $easyOptions
     */
    private function renderEasyGatePage(string $redirect, string $verifyApi, string $easyCdnUrl, array $easyOptions): string
    {
        $easyScriptSrc = htmlspecialchars($easyCdnUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $redirectJson = $this->safeJsonEncode($redirect);
        $verifyApiJson = $this->safeJsonEncode($verifyApi);
        $easyOptionsJson = $this->safeJsonEncode($easyOptions);

        return <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>AgeCheck Gate</title>
</head>
<body>
  <script src="{$easyScriptSrc}"></script>
  <script>
    const redirect = {$redirectJson};
    const verifyApi = {$verifyApiJson};
    const easyConfig = {$easyOptionsJson};

    const onSuccess = async (jwt, payload) => {
      const res = await fetch(verifyApi, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jwt, payload, redirect })
      });
      const out = await res.json();
      if (out.verified && typeof out.redirect === 'string') {
        window.location.assign(out.redirect);
      }
    };

    const onFailure = (err) => {
      console.error('AgeCheck verification failed', err);
    };

    easyConfig.onSuccess = onSuccess;
    easyConfig.onFailure = onFailure;
    window.AgeCheck.AgeGate.init(easyConfig);
  </script>
</body>
</html>
HTML;
    }

    private function safeJsonEncode($value): string
    {
        try {
            $json = json_encode($value, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new \RuntimeException('Failed to encode gate page configuration.', 0, $exception);
        }

        if (!is_string($json)) {
            throw new \RuntimeException('Failed to encode gate page configuration.');
        }

        return str_replace('<', '\\u003c', $json);
    }
}
