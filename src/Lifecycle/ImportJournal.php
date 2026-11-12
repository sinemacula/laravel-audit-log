<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Where an import batch stands in the lifecycle journal, read inside a
 * lifecycle transaction so no other operation journals it meanwhile.
 *
 * Reads start at the batch's start time, so they grow with recent imports,
 * never with the rest of the journal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportJournal
{
    /** @var int Journal rows read by one statement. */
    private const int PAGE = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     */
    public function __construct(

        /** Verifies each row read. */
        private JournalSigner $signer,
    ) {}

    /**
     * The batch's start row and its finish row with payload, each `null` when
     * absent.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $batchId
     * @param  string  $since
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: ?array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function of(Connection $connection, string $batchId, string $since): array
    {
        $start = $this->find($connection, JournalKind::IMPORT_STARTED, $batchId, $since);

        if ($start === null) {
            return [null, null];
        }

        return [$start[0], $this->find($connection, JournalKind::IMPORT_FINISHED, $batchId, $since)];
    }

    /**
     * The first row of the kind since `$since` whose payload names the batch.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  string  $batchId
     * @param  string  $since
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function find(Connection $connection, JournalKind $kind, string $batchId, string $since): ?array
    {
        $after = 0;

        do {
            $page = $connection->table(LifecycleTables::journalTable())
                ->useWritePdo()
                ->where('kind', $kind->value)
                ->where('occurred_at', '>=', $since)
                ->where('sequence', '>', $after)
                ->orderBy('sequence')
                ->limit(self::PAGE)
                ->get()
                ->all();

            foreach ($page as $stored) {
                [$row, $payload] = $this->verified((array) $stored);

                if (($payload['batch_id'] ?? null) === $batchId) {
                    return [$row, $payload];
                }

                $after = $row->sequence;
            }
        } while (count($page) === self::PAGE);

        return null;
    }

    /**
     * The stored row and its decoded payload, once both verify.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function verified(#[\SensitiveParameter] array $stored): array
    {
        $id = is_string($stored['id'] ?? null) ? $stored['id'] : null;

        try {
            $row = JournalRow::fromRow($stored, true);

            if (!$row->hasPayloadOfItsDigest() || !$this->signer->verifies($row)) {
                throw JournalBrokenException::at(Finding::JOURNAL_SIGNATURE, $row->id);
            }

            return [$row, $row->payloadMap() ?? []];
        } catch (UnknownKeyException) {
            throw JournalBrokenException::at(Finding::JOURNAL_KEY, $id);
        } catch (\JsonException|\UnexpectedValueException) {
            throw JournalBrokenException::at(Finding::JOURNAL_MALFORMED, $id);
        }
    }
}
