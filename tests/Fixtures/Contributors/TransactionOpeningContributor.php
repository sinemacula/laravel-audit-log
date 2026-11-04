<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Contributors;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Records\Contribution;

/**
 * An application's contributor that begins a transaction on the storage
 * connection and leaves it open, as code that opens one and returns early
 * would, so the record it contributes to is inserted inside it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TransactionOpeningContributor implements ContextContributor
{
    /**
     * Begin a transaction on the storage connection, and contribute nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function contribute(Contribution $contribution): void
    {
        DB::connection(StorageConnection::name())->beginTransaction();
    }
}
