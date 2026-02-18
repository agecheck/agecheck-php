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
use AgeCheck\Gate;

require __DIR__.'/../vendor/autoload.php';

$config = new Config([
    'hmacSecret' => 'replace-this-with-at-least-32-random-bytes',
    'gatePage'   => '/agecheck_gate.php',
]);

$gate = new Gate($config);

// This page is protected
$gate->requireVerifiedOrRedirect();

$verifiedPayload = $gate->verifiedCookiePayload();
if (!is_array($verifiedPayload) || !isset($verifiedPayload['exp']) || !is_int($verifiedPayload['exp'])) {
    header('Location: /agecheck_gate.php?redirect=%2Fprotected_index.php');
    exit;
}

$expiresAtUnix = $verifiedPayload['exp'];
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>Restricted Content</title>
  <style>
    :root{--bg:#0b0d14;--text:#f9fafb;--muted:#cbd5e1;--accent2:#818cf8}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--text);background:radial-gradient(circle at 20% 0%, #1e1b4b 0%, #0b0d14 48%, #090b11 100%)}
    header{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:rgba(3,6,12,.66);border-bottom:1px solid rgba(255,255,255,.08)}
    .logo{font-size:1.35rem;font-weight:800}.me{color:var(--accent2)}
    main{padding:18px;display:grid;gap:12px}
    .card{border-radius:16px;border:1px solid rgba(255,255,255,.08);background:rgba(20,25,42,.85);overflow:hidden}
    .media{
      min-height:220px;
      background-image:
        linear-gradient(180deg, rgba(9,12,22,.08), rgba(9,12,22,.55)),
        url("https://images.unsplash.com/photo-1514790193030-c89d266d5a9d?auto=format&fit=crop&w=1200&q=80");
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }
    .content{padding:14px}
    h1{margin:0 0 8px;font-size:1.5rem}
    p{margin:0;color:var(--muted);line-height:1.45}
    .status{display:flex;gap:8px;align-items:center;margin-top:10px}
    .pill{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;padding:.36rem .56rem;border-radius:999px;border:1px solid rgba(16,185,129,.45);color:#a7f3d0;background:rgba(3,24,20,.65)}
    .timer{font-size:.8rem;color:var(--muted)}
    button{border:1px solid rgba(255,255,255,.2);color:var(--muted);background:rgba(255,255,255,.06);border-radius:999px;font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;padding:.42rem .65rem;cursor:pointer}
  </style>
</head>
<body>
  <header>
    <div class="logo">AgeCheck<span class="me">.me</span></div>
    <button id="resetBtn" type="button">Reset Verification</button>
  </header>
  <main>
    <section class="card">
      <div class="media" role="img" aria-label="Restricted content background"></div>
      <div class="content">
        <h1>Age Restricted Content</h1>
        <p>Access granted. This content is served only after server-side signed cookie validation.</p>
        <div class="status">
          <span class="pill">Verified</span>
          <span class="timer" id="remaining"></span>
        </div>
      </div>
    </section>
  </main>
  <script>
    const EXPIRES_AT = <?php echo (string)$expiresAtUnix; ?>;
    function formatRemaining(seconds){
      if(seconds <= 0) return "Session expired";
      const h = Math.floor(seconds / 3600);
      const m = Math.floor((seconds % 3600) / 60);
      return h > 0 ? h + "h " + m + "m remaining" : m + "m remaining";
    }
    function updateRemaining(){
      const now = Math.floor(Date.now() / 1000);
      const el = document.getElementById("remaining");
      if(!el) return;
      el.textContent = formatRemaining(EXPIRES_AT - now);
    }
    updateRemaining();
    setInterval(updateRemaining, 15000);

    document.getElementById("resetBtn").addEventListener("click", async () => {
      try {
        await fetch("/session_reset_api.php", { method: "POST", credentials: "same-origin" });
      } finally {
        window.location.assign("/protected_index.php");
      }
    });
  </script>
</body>
</html>
