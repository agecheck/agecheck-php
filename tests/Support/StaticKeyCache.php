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

namespace AgeCheck\Tests\Support;

use AgeCheck\KeyCache;

final class StaticKeyCache extends KeyCache
{
    /** @var array<string,mixed> */
    private array $keys;

    /**
     * @param array<string,mixed> $keys
     */
    public function __construct(array $keys)
    {
        $this->keys = $keys;
        parent::__construct(sys_get_temp_dir() . '/agecheck-test-cache', 1, 1);
    }

    /**
     * @return array<string,mixed>
     */
    public function getOrFetch(string $url): array
    {
        return $this->keys;
    }
}
