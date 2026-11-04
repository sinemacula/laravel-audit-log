<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Writes the lifecycle journal as the package does, and alters it as an
 * attacker with the database's credentials could: rows signed through the
 * container's journal signer, each at the next sequence and linked to the row
 * before it, in the configured log, at the container's clock; raw edits of a
 * stored row's columns; and the stored rows as raw rows.
 *
 * A row of a kind that carries an authority is written with one, unless a test
 * gives another. The rows are written on the storage connection, which is the
 * maintenance connection unless a test configures another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait WritesTheJournal
{
    /** @var array{0: string, 1: string} The authority a row of a kind that carries one is written with, unless a test gives another. */
    protected const array JOURNAL_AUTHORITY = ['App\Models\User', '7'];

    /** @var string The reason a row of a kind that carries an authority is written with, unless a test gives another. */
    protected const string JOURNAL_REASON = 'case.review';

    /**
     * Append a row of the kind, with the payload and the columns given, signed
     * at the next sequence and linked to the head, and return it as it was
     * stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  array<array-key, mixed>  $payload
     * @param  ?string  $holdId
     * @param  ?string  $sealId
     * @param  ?array{0: string, 1: string}  $authority
     * @param  ?string  $reason
     * @param  ?string  $externalReference
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    protected function journalRow(
        JournalKind $kind,
        array $payload = [],
        ?string $holdId = null,
        ?string $sealId = null,
        ?array $authority = null,
        ?string $reason = null,
        ?string $externalReference = null,
    ): JournalRow {
        $head      = $this->journal()->where('sequence', '>=', 1)->orderByDesc('sequence')->first(['sequence', 'hmac']);
        $sequence  = $head === null ? 1 : (int) $head->sequence + 1;
        $now       = app(Clock::class)->now();
        $carries   = $kind->carriesAuthority();
        $authority = $authority ?? ($carries ? self::JOURNAL_AUTHORITY : null);

        $draft = JournalRow::draft(
            Str::uuid7($now)->toString(),
            $sequence,
            app(SealSettings::class)->logId(),
            $kind,
            Str::uuid7($now)->toString(),
            StoredTime::format($now),
            $authority,
            $reason ?? ($authority === null ? null : self::JOURNAL_REASON),
            $externalReference,
            $sealId,
            $holdId,
            $payload,
            $head === null ? null : (string) $head->hmac,
        );

        $signed = app(JournalSigner::class)->sign($draft);

        $this->journal()->insert($signed->toRow());

        return $signed;
    }

    /**
     * Append a hold of the hold id, and return it as it was stored.
     *
     * @param  string  $holdId
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    protected function journalHold(string $holdId): JournalRow
    {
        return $this->journalRow(JournalKind::HOLD, ['hold_id' => $holdId, 'basis' => 'legal_claim', 'review_by' => null], $holdId);
    }

    /**
     * Change the stored row at the sequence's columns, as raw values, signing
     * nothing again.
     *
     * @param  int  $sequence
     * @param  array<string, int|string|null>  $columns
     * @return void
     */
    protected function tamperJournal(int $sequence, array $columns): void
    {
        $this->journal()->where('sequence', $sequence)->update($columns);
    }

    /**
     * Every stored journal row as its raw row, by sequence: each column as the
     * engine returns it.
     *
     * @return list<array<string, scalar|null>>
     */
    protected function journalRows(): array
    {
        /** @var list<array<string, scalar|null>> $rows */
        $rows = array_map(static fn (object $row): array => (array) $row, $this->journal()->orderBy('sequence')->get()->all());

        return $rows;
    }

    /**
     * A query of the journal table on the storage connection's writer.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function journal(): Builder
    {
        return DB::connection(StorageConnection::name())->table(LifecycleTables::journalTable())->useWritePdo();
    }
}
