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

final class ErrorCode
{
    public const INVALID_INPUT = 'invalid_input';
    public const INVALID_HEADER = 'invalid_header';
    public const INVALID_ISSUER = 'invalid_issuer';
    public const INVALID_CREDENTIAL = 'invalid_credential';
    public const INVALID_AGE_TIER = 'invalid_age_tier';
    public const INSUFFICIENT_AGE_TIER = 'insufficient_age_tier';
    public const SESSION_BINDING_REQUIRED = 'session_binding_required';
    public const SESSION_BINDING_MISMATCH = 'session_binding_mismatch';
    public const TOKEN_EXPIRED = 'token_expired';
    public const TOKEN_NOT_YET_VALID = 'token_not_yet_valid';
    public const INVALID_SIGNATURE = 'invalid_signature';
    public const UNKNOWN_KEY_ID = 'unknown_key_id';
    public const INVALID_TOKEN_TYPE = 'invalid_token_type';
    public const VERIFY_FAILED = 'verify_failed';

    private function __construct()
    {
    }
}

