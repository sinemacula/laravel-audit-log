<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Retention policy contract: how long the entries of a category, in a tenant,
 * are kept before a prune may delete them, and how long they must stay
 * readable.
 *
 * The package binds `Lifecycle\ConfiguredRetentionPolicy`, which reads
 * `audit-log.retention.*`; an application rebinds the contract for a policy the
 * configuration cannot express. An implementation must keep no state between
 * calls and never reads the entries table. A prune asks it once per distinct
 * category and tenant pair it meets, and its answers are frozen for the rest of
 * that run.
 *
 * The package records the basis the operator supplies and never decides legal
 * necessity: retention says when an entry may go, preservation how long it must
 * stay readable. Preservation is enforced against pruning: a retention shorter
 * than its preservation is refused. Whatever an implementation throws stops the
 * run; the chunks it already committed stand.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RetentionPolicy
{
    /**
     * The policy's version: 1 to 64 characters of clean text, which must change
     * whenever any answer of the policy could, so the journal records each
     * policy a prune ran under.
     *
     * @return string
     */
    public function version(): string;

    /**
     * How many days the entries of the category in the tenant are kept, from 1
     * to 36500, counted back from the run's midnight, or `null` to keep them
     * forever. A tenantless entry is asked with a `null` tenant.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return ?int
     */
    public function retainFor(string $category, ?Reference $tenant): ?int;

    /**
     * How many days the entries of the category in the tenant must stay
     * readable, from 1 to 36500, `PHP_INT_MAX` for forever, or `null` when
     * nothing obliges the package to keep them. A retention shorter than this
     * is refused.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return ?int
     */
    public function preserveFor(string $category, ?Reference $tenant): ?int;
}
