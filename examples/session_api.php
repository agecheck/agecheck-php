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

use AgeCheck\Gate;

require __DIR__ . '/../vendor/autoload.php';
header('Content-Type: application/json');

$config = require __DIR__ . '/config.php';
$gate = new Gate($config);

$payload = $gate->verifiedCookiePayload();
if ($payload === null) {
    echo json_encode(['verified' => false]);
    exit;
}

echo json_encode([
    'verified' => true,
    'ageTier' => $payload['level'],
    'expiresAt' => $payload['exp'],
    'remainingSeconds' => max(0, $payload['exp'] - time()),
]);
