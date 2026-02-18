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

require __DIR__ . '/../vendor/autoload.php';

$config = new Config([
    'hmacSecret' => 'replace-this-with-at-least-32-random-bytes',
    'verifyApi' => '/ageverify_api.php',
]);

$gate = new Gate($config);

$redirect = isset($_GET['redirect']) && is_string($_GET['redirect']) ? $_GET['redirect'] : '/';
$useEasy = isset($_GET['easy']) && $_GET['easy'] === '1';

echo $gate->renderGatePage([
    'redirect' => $redirect,
    'easyAgeGate' => $useEasy,
    'easyAgeGateOptions' => [
        'title' => 'Age Restricted Content',
        'subtitle' => 'Please confirm your age anonymously using AgeCheck.me.',
        'verifyButtonText' => 'Verify Now',
    ],
]);
