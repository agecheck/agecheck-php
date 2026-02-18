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

final class Result
{
    private bool $ok;
    /** @var array<string,mixed>|null */
    private ?array $claims;
    private ?string $code;
    private ?string $error;

    /**
     * @param array<string,mixed>|null $claims
     */
    private function __construct(bool $ok, ?array $claims = null, ?string $code = null, ?string $error = null)
    {
        $this->ok = $ok;
        $this->claims = $claims;
        $this->code = $code;
        $this->error = $error;
    }

    /**
     * @param array<string,mixed> $claims
     */
    public static function success(array $claims): self
    {
        return new self(true, $claims, null, null);
    }

    public static function failure(string $code, string $message): self
    {
        return new self(false, null, $code, $message);
    }

    public function isOk(): bool
    {
        return $this->ok;
    }

    /**
     * @return array<string,mixed>|null
     */
    public function claims(): ?array
    {
        return $this->claims;
    }

    public function code(): ?string
    {
        return $this->code;
    }

    public function error(): ?string
    {
        return $this->error;
    }
}
