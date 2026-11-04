<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Querying;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * An access policy that answers with the closure it is given, which may throw,
 * and keeps every viewer and purpose it was asked for, in order, the viewer
 * exactly as it was handed over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClosurePolicy implements AuditAccessPolicy
{
    /** @var list<array{0: \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference, 1: \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose}> Each viewer and purpose it was asked for, in order. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference, \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose): \SineMacula\Laravel\AuditLog\Access\AccessScope  $answer
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function __construct(

        /** What answers each viewer and purpose with a scope. */
        private readonly \Closure $answer,
    ) {}

    /**
     * The scope the closure answers for the viewer and the purpose, once they
     * are kept.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    #[\Override]
    public function scope(#[\SensitiveParameter] Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        $this->asked[] = [$viewer, $purpose];

        return ($this->answer)($viewer, $purpose);
    }

    /**
     * Each viewer and purpose it was asked for, in order.
     *
     * @return list<array{0: \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference, 1: \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
