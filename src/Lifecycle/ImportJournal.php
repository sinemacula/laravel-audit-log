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
 * Where an import batch stands in the lifecycle journal: the `import_started`
 * row that names it, if any, and its `import_finished` row, if any, read inside
 * a lifecycle transaction once its replay has verified the chain to its head,
 * so no other operation journals the batch between the read and what the caller
 * appends.
 *
 * The rows of each kind are read by kind and time, from the time the batch
 * started, which no row of its import precedes, a page at a time in sequence
 * order, by the kind's index; each row read must verify under the key it names
 * and hold the payload its digest signs, or the operation fails closed with a
 * `JournalBrokenException`. The payload's `batch_id` names the batch, so what
 * is read grows with the imports started and finished since the batch started,
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

        /** The signer each row read is verified with. */
        private JournalSigner $signer,
    ) {}

    /**
     * The batch's start row, or `null` when no `import_started` names it, and
     * its finish row with its decoded payload, or `null` while it is open.
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
     * The first row of the kind since the time given whose payload names the
     * batch, with its decoded payload, or `null` when none does.
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
     * The stored row and its decoded payload, once its signature and its
     * payload's digest verify.
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
