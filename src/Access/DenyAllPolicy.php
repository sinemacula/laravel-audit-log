<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Access;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The access policy bound until an application binds its own: it denies every
 * viewer for every purpose, and each such read is recorded as denied.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DenyAllPolicy implements AuditAccessPolicy
{
    /**
     * A denied scope, whoever the viewer and whatever the purpose.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    #[\Override]
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        return AccessScope::none();
    }
}
