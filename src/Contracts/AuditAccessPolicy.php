<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Audit access policy contract: the entries of the trail a viewer may see for a
 * purpose, as a scope compiled into every statement run for that viewer.
 *
 * The viewer is the application's assertion of who is reading, never proof. The
 * scope is resolved on every terminal call, so an implementation keeps no state
 * and never reads the entries table.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuditAccessPolicy
{
    /**
     * The entries the viewer may see for the purpose: `AccessScope::none()`,
     * `AccessScope::all()`, or a scope narrowed from either.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope;
}
