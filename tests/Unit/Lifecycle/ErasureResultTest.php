<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult;

/**
 * Unit tests for what an erasure did: every field as given, the blocked reasons
 * each once and sorted bytewise, always committed and not yet recorded, the
 * result of an owner already erased, the result once its record is written, and
 * the map it gives under snake-case keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureResult::class)]
final class ErasureResultTest extends TestCase
{
    /** @var string The operation every result is of. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The erasure row every result names. */
    private const string ERASURE = '01932b4e-9000-7000-8000-0000000000e1';

    /** @var string The owner's fingerprint. */
    private const string FINGERPRINT = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

    /**
     * Every field is kept as given, the blocked reasons each once and sorted
     * bytewise; a result is always committed and, until its record is written,
     * not recorded.
     *
     * @return void
     */
    public function testKeepsWhatTheErasureDid(): void
    {
        $result = self::partialResult();

        self::assertSame(self::OPERATION, $result->operationId);
        self::assertSame(self::ERASURE, $result->erasureId);
        self::assertSame(ErasureStatus::PARTIAL, $result->status);
        self::assertSame([self::FINGERPRINT, 'k1'], [$result->fingerprint, $result->fingerprintKey]);
        self::assertSame([2, 1, 7], [$result->keysDestroyed, $result->keysKept, $result->entriesAffected]);
        self::assertSame(['held:a', 'preserved:billing'], $result->blocked);
        self::assertTrue($result->pendingAccepted);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
    }

    /**
     * An owner already erased that holds no key gives a result that names no
     * erasure row and counts nothing.
     *
     * @return void
     */
    public function testAnAlreadyErasedOwnerNamesNoRow(): void
    {
        $result = ErasureResult::alreadyErased(self::OPERATION, self::FINGERPRINT, 'k1');

        self::assertNull($result->erasureId);
        self::assertSame(ErasureStatus::ALREADY_ERASED, $result->status);
        self::assertSame([0, 0, 0], [$result->keysDestroyed, $result->keysKept, $result->entriesAffected]);
        self::assertSame([], $result->blocked);
        self::assertFalse($result->pendingAccepted);
        self::assertTrue($result->committed);
    }

    /**
     * The result with its record written changes nothing else.
     *
     * @return void
     */
    public function testWithRecordedKeepsEverythingElse(): void
    {
        $result   = self::partialResult();
        $recorded = $result->withRecorded(true);

        self::assertTrue($recorded->recorded);
        self::assertSame([...$result->toArray(), 'recorded' => true], $recorded->toArray());
        self::assertFalse($recorded->withRecorded(false)->recorded);
    }

    /**
     * The map names every field under its snake-case key, in order.
     *
     * @return void
     */
    public function testTheMapNamesEveryField(): void
    {
        self::assertSame([
            'operation_id'      => self::OPERATION,
            'committed'         => true,
            'recorded'          => false,
            'erasure_id'        => self::ERASURE,
            'status'            => 'partial',
            'owner_fingerprint' => self::FINGERPRINT,
            'fingerprint_key'   => 'k1',
            'keys_destroyed'    => 2,
            'keys_kept'         => 1,
            'entries_affected'  => 7,
            'blocked'           => ['held:a', 'preserved:billing'],
            'pending_accepted'  => true,
        ], self::partialResult()->toArray());
    }

    /**
     * A partial result of the erasure every test describes.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult
     */
    private static function partialResult(): ErasureResult
    {
        return new ErasureResult(self::OPERATION, self::ERASURE, ErasureStatus::PARTIAL, self::FINGERPRINT, 'k1', 2, 1, 7, ['preserved:billing', 'held:a', 'held:a'], true);
    }
}
