<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Anchors the committed seals the anchor does not hold yet, in sequence order,
 * at most `integrity.anchor.batch` a pass, stopping at the first it cannot
 * anchor.
 *
 * The anchor's own head, never the anchor columns the writer may edit, decides
 * which seals are pending, and only a seal that verifies is anchored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Anchorer
{
    /** @var int Longest receipt kept, once encoded, in bytes. */
    public const int MAX_RECEIPT_BYTES = 4096;

    /** @var string An anchor's name: 1 to 64 UTF-8 characters, as the `anchor` column holds. */
    private const string NAME_PATTERN = '/\A.{1,64}\z/su';

    /** @var int Longest failure class kept on a seal, in characters, as `anchor_error_class` holds. */
    private const int ERROR_CLASS_MAX_CHARACTERS = 191;

    /** @var int Receipt JSON flags: always an object, with slashes, Unicode and float fractions kept. */
    private const int RECEIPT_FLAGS = JSON_FORCE_OBJECT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Database\IntegrityProgress  $progress
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The anchor the seals are kept in. */
        private CheckpointAnchor $anchor,

        /** The signer that checks each seal's signature before it is anchored. */
        private SealSigner $signer,

        /** The settings the batch is read from. */
        private AnchorSettings $settings,

        /** The progress the last anchoring and the last failure are recorded in. */
        private IntegrityProgress $progress,

        /** The clock the time of each anchoring is read from. */
        private Clock $clock,

        /** The connections the storage connection is resolved from. */
        private DatabaseManager $database,
    ) {}

    /**
     * Anchor the seals the anchor does not hold yet, in sequence order, until
     * the batch is done or a seal cannot be anchored.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\AnchorResult
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function anchorPending(): AnchorResult
    {
        if ($this->anchor instanceof NullAnchor) {
            return new AnchorResult(false);
        }

        $result = new AnchorResult;
        $name   = $this->anchor->name();

        if (preg_match(self::NAME_PATTERN, $name) !== 1) {
            $result->unavailable(null, \UnexpectedValueException::class);

            return $result;
        }

        foreach ($this->pending($name) as $seal) {

            $this->anchorOne($seal, $name, $result);

            if ($result->isStopped()) {
                break;
            }
        }

        $this->refuseOutsideTheChain($result);
        $this->recordLastAnchored($name, $result);

        return $result;
    }

    /**
     * The seals to anchor in this pass, in sequence order, at most the batch:
     * those after the point the anchor holds every seal to, and those up to it
     * whose receipt was never written.
     *
     * @param  string  $name
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    private function pending(string $name): array
    {
        $batch = $this->settings->batch();
        $held  = $this->heldThrough($name);
        $after = $this->checkpoints()->where('sequence', '>', $held)->orderBy('sequence')->limit($batch)->get()->all();
        $lost  = $held === 0 ? [] : $this->checkpoints()
            ->whereNull('anchored_at')
            ->whereBetween('sequence', [1, $held])
            ->orderBy('sequence')
            ->limit($batch)
            ->get()
            ->all();

        /** @var list<array<string, scalar|null>> $seals */
        $seals = array_map(static fn (object $seal): array => (array) $seal, [...$lost, ...$after]);

        return array_slice($seals, 0, $batch);
    }

    /**
     * The sequence the anchor holds every seal to: its head when it can report
     * one, and otherwise the last seal progress records it anchored under its
     * name, 0 when there is none.
     *
     * @param  string  $name
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function heldThrough(string $name): int
    {
        if ($this->anchor->supportsDiscovery()) {
            try {
                return $this->anchor->latest()->sequence ?? 0;
            } catch (\Throwable) {
                // Fall back to progress; a still unavailable anchor fails there
            }
        }

        $last = $this->progress->get(IntegrityProgress::ANCHOR_LAST);

        return ($last['anchor'] ?? null) === $name ? max(0, IntegerSetting::parse($last['sequence'] ?? null) ?? 0) : 0;
    }

    /**
     * Refuse the first seal stored at a sequence below 1, which is outside the
     * chain.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function refuseOutsideTheChain(AnchorResult $result): void
    {
        $outside = $this->checkpoints()->where('sequence', '<', 1)->orderBy('sequence')->first();

        if ($outside === null) {
            return;
        }

        $seal = (array) $outside;

        $result->refused(IntegerSetting::parse($seal['sequence'] ?? null) ?? 0, self::idOf($seal), Finding::SEAL_MALFORMED);
    }

    /**
     * Anchor the seal once it verifies and record its receipt, or record why it
     * could not be anchored, which stops the pass.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function anchorOne(array $seal, string $name, AnchorResult $result): void
    {
        $summary = $this->summaryOf($seal);

        if ($summary instanceof Finding) {
            $result->refused(IntegerSetting::parse($seal['sequence'] ?? null) ?? 0, self::idOf($seal), $summary);

            return;
        }

        try {
            $receipt = self::encodedReceipt($this->anchor->anchor($summary));

            $this->checkpoints()->where('id', $summary->sealId)->update([
                'anchor'             => $name,
                'anchor_receipt'     => $receipt,
                'anchored_at'        => StoredTime::toStorage(StoredTime::format($this->clock->now())),
                'anchor_error_class' => null,
            ]);
        } catch (AnchorConflictException) {
            $this->recordError($summary->sealId, AnchorConflictException::class);
            $result->conflicted($summary->sequence, $summary->sealId);

            return;
        } catch (\Throwable $failure) {
            $this->recordUnavailable($summary, self::classOf($failure), $result);

            return;
        }

        $result->anchored($summary->sequence);
    }

    /**
     * The seal's summary under its recomputed digest, or the finding it is
     * refused for.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding|\SineMacula\Laravel\AuditLog\Integrity\SealSummary
     *
     * @throws \InvalidArgumentException
     */
    private function summaryOf(array $seal): Finding|SealSummary
    {
        try {
            $envelope = SealEnvelope::fromRow($seal);
            $digest   = $envelope->digest();
        } catch (\UnexpectedValueException) {
            return Finding::SEAL_MALFORMED;
        }

        return $this->findingOf($envelope, $digest, $seal) ?? SealSummary::of($envelope, $digest);
    }

    /**
     * The finding the seal is refused for once its fields are read, or `null`
     * when its digest and signature verify.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $envelope
     * @param  string  $digest
     * @param  array<array-key, mixed>  $seal
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function findingOf(SealEnvelope $envelope, string $digest, array $seal): ?Finding
    {
        $stored    = $seal['seal_digest'] ?? null;
        $signature = $seal['signature']   ?? null;

        if (!is_string($stored) || !is_string($signature)) {
            return Finding::SEAL_MALFORMED;
        }

        return hash_equals($digest, $stored) ? $this->signatureFinding($envelope, $signature) : Finding::SEAL_DIGEST;
    }

    /**
     * The finding the seal's signature gives, or `null` when it verifies under
     * the key the seal names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $envelope
     * @param  string  $signature
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function signatureFinding(SealEnvelope $envelope, string $signature): ?Finding
    {
        try {
            return $this->signer->verifies($envelope, $signature) ? null : Finding::SEAL_SIGNATURE;
        } catch (UnknownKeyException) {
            return Finding::SEAL_KEY;
        } catch (\UnexpectedValueException) {
            return Finding::SEAL_MALFORMED;
        }
    }

    /**
     * Keep the class of the failure on the seal and in progress, and record the
     * anchor as unavailable from the seal on.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $summary
     * @param  string  $class
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function recordUnavailable(SealSummary $summary, string $class, AnchorResult $result): void
    {
        $this->recordError($summary->sealId, $class);

        $now = $this->clock->now();

        $this->progress->put(IntegrityProgress::ANCHOR_LAST_FAILURE, ['sequence' => $summary->sequence, 'class' => $class, 'at' => StoredTime::format($now)], $now);

        $result->unavailable($summary->sequence, $class);
    }

    /**
     * Keep the class of the failure on the seal, writing that column alone.
     *
     * @param  string  $sealId
     * @param  string  $class
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function recordError(string $sealId, string $class): void
    {
        $this->checkpoints()->where('id', $sealId)->update(['anchor_error_class' => $class]);
    }

    /**
     * Record the last seal the pass anchored in progress, under the anchor's
     * name, when it anchored any.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchorResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function recordLastAnchored(string $name, AnchorResult $result): void
    {
        $sequence = $result->lastAnchored();

        if ($sequence === null) {
            return;
        }

        $now = $this->clock->now();

        $this->progress->put(IntegrityProgress::ANCHOR_LAST, ['sequence' => $sequence, 'anchor' => $name, 'anchored_at' => StoredTime::format($now)], $now);
    }

    /**
     * A query of the seals table on the storage connection's writer.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function checkpoints(): Builder
    {
        return $this->database->connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->useWritePdo();
    }

    /**
     * The receipt as it is kept beside the seal: its JSON, once it is known to
     * be a map of string keys to scalars or `null` no longer than the bound.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $receipt
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function encodedReceipt(array $receipt): string
    {
        foreach ($receipt as $key => $value) {
            if (!is_string($key) || ($value !== null && !is_scalar($value))) {
                throw new \UnexpectedValueException('An anchor\'s receipt must be a map of string keys to scalars or null.');
            }
        }

        try {
            $encoded = json_encode($receipt, self::RECEIPT_FLAGS);
        } catch (\JsonException) {
            throw new \UnexpectedValueException('An anchor\'s receipt cannot be encoded as JSON.');
        }

        if (strlen($encoded) > self::MAX_RECEIPT_BYTES) {
            throw new \UnexpectedValueException(sprintf('An anchor\'s receipt must be at most %d bytes once encoded.', self::MAX_RECEIPT_BYTES));
        }

        return $encoded;
    }

    /**
     * The stored seal's id when it is a lower-case UUID, and `null` otherwise,
     * so a malformed id is never passed on.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @return ?string
     */
    private static function idOf(array $seal): ?string
    {
        $id = $seal['id'] ?? null;

        return is_string($id) && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1 ? $id : null;
    }

    /**
     * The class of the failure, as it is kept: an anonymous class named without
     * its file, cut to the column's 191 characters.
     *
     * @param  \Throwable  $failure
     * @return string
     */
    private static function classOf(#[\SensitiveParameter] \Throwable $failure): string
    {
        return mb_substr(get_debug_type($failure), 0, self::ERROR_CLASS_MAX_CHARACTERS);
    }
}
