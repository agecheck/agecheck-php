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

return new Config([
    // REQUIRED: at least 32 bytes of random secret material.
    'hmacSecret' => 'YOUR_32_BYTE_SECRET',

    // Unified deployment mode:
    // Config::DEPLOYMENT_PRODUCTION | Config::DEPLOYMENT_DEMO
    'deploymentMode' => Config::DEPLOYMENT_PRODUCTION,
    'allowCustomIssuer' => false,

    // Minimum accepted age tier. Example: 18 means 18+ or higher.
    'requiredAge' => 18,

    // Optional overrides:
    'cookieTtl'  => 86400,
    'gatePage'   => '/agecheck_gate.php',
    'verifyApi'  => '/ageverify_api.php',
]);
