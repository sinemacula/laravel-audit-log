<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
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
use SineMacula\Laravel\AuditLog\Support\UuidV7;

/**
 * The one writer of the lifecycle journal, appending only onto the head a
 * replay verified in the same transaction, behind the lifecycle lock.
 *
 * The caller carries the returned replay forward only once its transaction has
 * committed.
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

        /** Signs every row. */
        private JournalSigner $signer,

        /** Gives the log id every row belongs to. */
        private SealSettings $settings,

        /** Stamps every row. */
        private Clock $clock,
    ) {}

    /**
     * Append a row of the kind onto the replay's head and return the replay
     * that accepted it.
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
            UuidV7::at($now),
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
     * Refuse a stored head that is not the replay's: a row was deleted,
     * replaced or added since the replay read it.
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
     * Refuse an append outside a transaction, or whose authority does not match
     * its kind.
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
     * Insert the signed row; a failure is rethrown masked so no binding reaches
     * a reporter.
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
