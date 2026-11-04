<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Audit access policy contract: the seam deciding which entries of the trail a
 * viewer may see for a purpose, as an access scope the package compiles into
 * every statement it runs for that viewer.
 *
 * The package binds `Access\DenyAllPolicy`, which denies every viewer, so the
 * trail reads nothing until an application binds a policy of its own. The
 * viewer is the one the application gave `visibleTo()`, authenticated by the
 * application: a `Reference` viewer is an assertion of who is reading, never
 * proof of it. The scope is resolved again on every terminal call, so an
 * implementation must keep no state between calls and must not read the entries
 * table. Anything it throws is recorded as a failed read and propagates to the
 * caller unchanged.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuditAccessPolicy
{
    /**
     * The scope of entries the viewer may see for the purpose:
     * `AccessScope::none()` to see nothing, `AccessScope::all()` to see every
     * entry, or a scope narrowed from either.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope;
}
