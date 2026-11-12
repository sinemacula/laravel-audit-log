<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Retention policy contract: how long the entries of a category in a tenant are
 * kept before a prune may delete them, and how long they must stay readable.
 *
 * An implementation keeps no state and never reads the entries table. A prune
 * freezes its answers for the run, and anything it throws stops the run.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RetentionPolicy
{
    /**
     * The policy's version, 1 to 64 characters of clean text, changed whenever
     * any answer could change.
     *
     * @return string
     */
    public function version(): string;

    /**
     * Days the category's entries in the tenant are kept, 1 to 36500 back from
     * the run's midnight, or `null` for forever; a tenantless entry is asked
     * with a `null` tenant.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return ?int
     */
    public function retainFor(string $category, ?Reference $tenant): ?int;

    /**
     * Days the entries must stay readable, 1 to 36500 or `PHP_INT_MAX` for
     * forever, or `null` when nothing obliges keeping them; a shorter retention
     * is refused.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return ?int
     */
    public function preserveFor(string $category, ?Reference $tenant): ?int;
}
