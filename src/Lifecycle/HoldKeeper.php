<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Places and releases holds and rebuilds their projection, each decided from
 * the verified journal under the lifecycle lock, never from the projection.
 *
 * Hold ids are never reused, so an id the chain ever placed is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HoldKeeper
{
    /** @var string A hold id the package mints: a lower-case UUID v7. */
    private const string UUID_V7_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldProjection  $projection
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** Runs every operation behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal every hold and release is appended to. */
        private Journal $journal,

        /** Verifies the journal for each replay. */
        private JournalSigner $signer,

        /** Gives the journal's log id. */
        private SealSettings $settings,

        /** The projection changed with each hold and release. */
        private HoldProjection $projection,

        /** Mints fresh hold and operation ids. */
        private Clock $clock,
    ) {}

    /**
     * Place a hold of the scope in one lifecycle transaction, under the hold id
     * given or a fresh one.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @param  ?\DateTimeInterface  $reviewBy
     * @param  ?string  $holdId
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function place(
        string $operationId,
        #[\SensitiveParameter] HoldScope $scope,
        Authority $authority,
        HoldBasis $basis,
        ?\DateTimeInterface $reviewBy,
        ?string $holdId = null,
    ): Hold {
        $this->transaction->confirm();

        [$hold] = $this->transaction->run(
            $operationId,
            fn (Connection $connection): array => $this->placeIn($connection, $this->replay()->verify($connection), $operationId, $scope, $authority, $basis, $reviewBy, $holdId),
        );

        return $hold;
    }

    /**
     * Place a hold inside the caller's lifecycle transaction, so an import's
     * start and its hold commit together.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @param  ?\DateTimeInterface  $reviewBy
     * @param  ?string  $holdId
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\Hold, 1: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public function placeIn(
        Connection $connection,
        JournalReplay $replay,
        string $operationId,
        #[\SensitiveParameter]
        HoldScope $scope,
        Authority $authority,
        HoldBasis $basis,
        ?\DateTimeInterface $reviewBy,
        ?string $holdId = null,
    ): array {
        $holdId ??= Str::uuid7($this->clock->now())->toString();

        self::checkPlaceable($replay, $holdId);

        $payload = [
            'hold_id'   => $holdId,
            'scope'     => $scope->toArray(),
            'basis'     => $basis->value,
            'review_by' => $reviewBy === null ? null : StoredTime::format($reviewBy),
        ];

        $next = $this->journal->append($connection, $replay, JournalKind::HOLD, $operationId, $authority, $payload, holdId: $holdId);
        $hold = self::placed($next, $holdId);

        $this->projection->insert($connection, $hold);

        return [$hold, $next];
    }

    /**
     * Release the active hold and return it as it was; a hold the verified
     * chain does not hold active is refused.
     *
     * @param  string  $operationId
     * @param  string  $holdId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function release(string $operationId, string $holdId, Authority $authority): Hold
    {
        self::checkHoldId($holdId);

        $this->transaction->confirm();

        return $this->transaction->run($operationId, function (Connection $connection) use ($operationId, $holdId, $authority): Hold {
            $replay = $this->replay()->verify($connection);
            $hold   = $replay->hold($holdId) ?? throw UnknownHoldException::for($holdId);

            $this->journal->append($connection, $replay, JournalKind::RELEASE, $operationId, $authority, ['hold_id' => $holdId], holdId: $holdId);
            $this->projection->delete($connection, $holdId);

            return $hold;
        });
    }

    /**
     * Rebuild the projection from the verified chain, returning how many holds
     * it now holds.
     *
     * @param  string  $operationId
     * @return int
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Throwable
     */
    public function rebuild(string $operationId): int
    {
        $this->transaction->confirm();

        return $this->transaction->run(
            $operationId,
            fn (Connection $connection): int => $this->projection->rebuild($connection, $this->replay()->verify($connection)->holds()),
        );
    }

    /**
     * The active holds in placement order, replayed from the verified chain.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Throwable
     */
    public function active(): array
    {
        $this->transaction->confirm();

        return $this->transaction->run(
            Str::uuid7($this->clock->now())->toString(),
            fn (Connection $connection): array => $this->replay()->verify($connection)->holds(),
        );
    }

    /**
     * A fresh replay of the configured log.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     *
     * @throws \InvalidArgumentException
     */
    private function replay(): JournalReplay
    {
        return JournalReplay::start($this->signer, $this->settings->logId());
    }

    /**
     * Refuse a hold id that is not a lower-case UUID v7.
     *
     * @param  string  $holdId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkHoldId(string $holdId): void
    {
        if (preg_match(self::UUID_V7_PATTERN, $holdId) === 1) {
            return;
        }

        throw new \InvalidArgumentException('A hold id must be a lower-case UUID v7.');
    }

    /**
     * Refuse a malformed hold id or one the chain ever placed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  string  $holdId
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkPlaceable(JournalReplay $replay, string $holdId): void
    {
        self::checkHoldId($holdId);

        if (!$replay->hasPlacedHold($holdId)) {
            return;
        }

        throw new \LogicException(sprintf('The hold id `%s` was placed before; a hold id is never reused.', $holdId));
    }

    /**
     * The hold the replay accepted under the id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  string  $holdId
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     *
     * @throws \LogicException
     */
    private static function placed(JournalReplay $replay, string $holdId): Hold
    {
        return $replay->hold($holdId) ?? throw new \LogicException('The journal accepted a hold its replay does not hold.');
    }
}
