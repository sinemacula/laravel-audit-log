<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Appends to the lifecycle journal, and only onto the head a replay verified:
 * the one writer of the journal, called inside a `MaintenanceTransaction` after
 * the replay was verified or advanced in the same transaction, behind the
 * lifecycle lock.
 *
 * The stored head is read first, and must be the replay's head, by its sequence
 * and its HMAC, else nothing is appended and the journal is broken: a row was
 * deleted, replaced or added since the replay read it. The row is then drafted
 * at the next sequence, linked to the head's HMAC, in the configured log, with
 * a fresh id and the clock's time, signed under the ring's signing key,
 * accepted by the replay, which refuses a transition the chain does not allow,
 * and inserted. The replay that accepted it is returned, holding it as its last
 * appended row, and the caller carries that replay forward only once its
 * transaction has committed.
 *
 * A kind that carries an authority is appended with one, and every other kind
 * without, so a hold, a release or an import always names who asked for it. A
 * second row at one sequence is refused by the journal's unique index, which
 * only an append outside the lifecycle lock could reach; it is a programming
 * error, never retried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Journal
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The signer every row is signed with. */
        private JournalSigner $signer,

        /** The settings the log id every row belongs to is read from. */
        private SealSettings $settings,

        /** The time every row is appended at. */
        private Clock $clock,
    ) {}

    /**
     * Append a row of the kind onto the replay's head, inside the lifecycle
     * transaction the connection holds, and return the replay that accepted it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  string  $operationId
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  array<array-key, mixed>  $payload
     * @param  ?string  $sealId
     * @param  ?string  $holdId
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public function append(
        Connection $connection,
        JournalReplay $replay,
        JournalKind $kind,
        string $operationId,
        ?Authority $authority,
        #[\SensitiveParameter]
        array $payload,
        ?string $sealId = null,
        ?string $holdId = null,
    ): JournalReplay {
        self::checkFrame($connection, $kind, $authority);

        $head = $replay->head();

        $this->checkHead($connection, $head);

        $now = $this->clock->now();

        $draft = JournalRow::draft(
            Str::uuid7($now)->toString(),
            ($head[0] ?? 0) + 1,
            $this->settings->logId(),
            $kind,
            $operationId,
            StoredTime::format($now),
            $authority === null ? null : [$authority->operator->type, $authority->operator->id],
            $authority?->reason,
            $authority?->externalReference,
            $sealId,
            $holdId,
            $payload,
            $head[1] ?? null,
        );

        $signed = $this->signer->sign($draft);
        $next   = $replay->accept($signed);

        self::insert($connection, $signed);

        return $next;
    }

    /**
     * Refuse a stored head that is not the replay's: a row at a later sequence,
     * a head row with another HMAC, or a head row where the replay saw none, or
     * none where it saw one.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  ?array{0: int, 1: string}  $head
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function checkHead(Connection $connection, ?array $head): void
    {
        $stored = $connection->table(LifecycleTables::journalTable())
            ->useWritePdo()
            ->where('sequence', '>=', 1)
            ->orderByDesc('sequence')
            ->first(['id', 'sequence', 'hmac']);

        $found = $stored === null ? null : [IntegerSetting::parse($stored->sequence ?? null), $stored->hmac ?? null];

        if ($found === $head) {
            return;
        }

        $id = $stored->id ?? null;

        throw JournalBrokenException::at(Finding::JOURNAL_GAP, is_string($id) ? $id : null);
    }

    /**
     * Refuse an append outside a transaction, or of a kind with an authority it
     * must not carry or without one it must.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkFrame(Connection $connection, JournalKind $kind, ?Authority $authority): void
    {
        if ($connection->transactionLevel() === 0) {
            throw new \LogicException('The journal is appended to only inside a lifecycle transaction.');
        }

        if ($kind->carriesAuthority() !== ($authority !== null)) {
            throw new \LogicException(sprintf('A journal row of the kind `%s` %s an authority.', $kind->value, $kind->carriesAuthority() ? 'must carry' : 'never carries'));
        }
    }

    /**
     * Insert the signed row; a row already at its sequence was appended outside
     * the lifecycle lock, a programming error never retried. Any other failure
     * is rethrown masked, so no binding of the row, a hold's scope or an
     * authority's reference, reaches a reporter.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return void
     *
     * @throws \LogicException
     */
    private static function insert(Connection $connection, #[\SensitiveParameter] JournalRow $journalRow): void
    {
        try {
            $connection->table(LifecycleTables::journalTable())->insert($journalRow->toRow());
        } catch (UniqueConstraintViolationException) { // @phpstan-ignore catch.neverThrown
            throw new \LogicException('The journal was appended to outside the lifecycle lock.');
        } catch (QueryException $failure) { // @phpstan-ignore catch.neverThrown
            FailureClassifier::rethrowMasked($failure);
        }
    }
}
