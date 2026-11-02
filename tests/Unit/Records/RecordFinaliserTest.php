<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Unit tests for the record finaliser: a record stamped with the clock's
 * instant in UTC, to the microsecond, never before the activity occurred, and
 * signed under the ring's signing key, the same bytes each time it is finalised
 * at one instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordFinaliser::class)]
final class RecordFinaliserTest extends TestCase
{
    /** @var string The id a captured record is pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The signing key's secret, as its own 32 bytes. */
    private const string SECRET = 'record-finaliser key secret 32!!';

    /**
     * Restore UUID generation after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Str::createUuidsNormally();

        parent::tearDown();
    }

    /**
     * The record is finalised as the signer signs it at the clock's instant:
     * the captured record kept, recorded then, under the ring's key and the
     * current integrity version, with the signer's HMAC; the finalised record
     * verifies once stored and read back.
     *
     * @return void
     */
    public function testStampsTheClocksTimeAndSigns(): void
    {
        $record    = self::record();
        $finalised = self::finaliser(FrozenClock::at('2026-11-01 12:00:01.500000'))->finalise($record);

        self::assertSame($record, $finalised->record);
        self::assertSame('2026-11-01T12:00:01.500000Z', $finalised->recordedAt);
        self::assertSame(RecordSigner::VERSION, $finalised->integrityVersion);
        self::assertSame('k2026', $finalised->keyId);
        self::assertSame(self::signer()->sign($record, '2026-11-01T12:00:01.500000Z')->hmac, $finalised->hmac);

        $codec = new RowCodec;

        self::assertTrue(self::signer()->verifies($codec->decode($codec->encode($finalised))));
    }

    /**
     * A clock that gives its instant in another time zone stamps the same
     * instant in UTC, with all six fractional digits, trailing zeros included.
     *
     * @return void
     */
    public function testRecordedAtIsTheClocksInstantInUtcWithMicroseconds(): void
    {
        $auckland = self::clock(CarbonImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-11-02 01:00:01.000010', 'Pacific/Auckland'));

        self::assertSame('2026-11-01T12:00:01.000010Z', self::finaliser($auckland)->finalise(self::record())->recordedAt);

        $whole = self::clock(CarbonImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-11-01 07:00:02.000000', 'America/New_York'));

        self::assertSame('2026-11-01T12:00:02.000000Z', self::finaliser($whole)->finalise(self::record())->recordedAt);
    }

    /**
     * A clock behind the time the activity occurred, by a microsecond or by an
     * hour, stamps the record with the time it occurred, so it is never
     * recorded before it; a clock exactly at it stamps that time too.
     *
     * @return void
     */
    public function testRecordedAtIsNeverBeforeTheActivityOccurred(): void
    {
        $record = self::record();

        foreach (['2026-11-01 12:00:00.123455', '2026-11-01 11:00:00.999999', '2026-11-01 12:00:00.123456'] as $instant) {

            $finalised = self::finaliser(FrozenClock::at($instant))->finalise($record);

            self::assertSame(RecordFactory::OCCURRED_AT, $finalised->recordedAt, "The clock at {$instant}.");
            self::assertSame(self::signer()->sign($record, RecordFactory::OCCURRED_AT)->hmac, $finalised->hmac, "The clock at {$instant}.");
        }

        self::assertSame('2026-11-01T12:00:00.123457Z', self::finaliser(FrozenClock::at('2026-11-01 12:00:00.123457'))->finalise($record)->recordedAt);
    }

    /**
     * Finalising one record twice at one instant gives the same finalised
     * record byte for byte, and at another instant the same captured content
     * with another time and HMAC.
     *
     * @return void
     */
    public function testFinalisingTwiceAtOneInstantGivesTheSameBytes(): void
    {
        $record    = self::record();
        $finaliser = self::finaliser(FrozenClock::at('2026-11-01 12:00:01.000001'));

        $first  = $finaliser->finalise($record);
        $second = $finaliser->finalise($record);

        self::assertSame($first->toArray(), $second->toArray());
        self::assertSame((new RowCodec)->encode($first), (new RowCodec)->encode($second));

        $later = self::finaliser(FrozenClock::at('2026-11-01 12:00:01.000002'))->finalise($record);

        self::assertNotSame($first->hmac, $later->hmac);
        self::assertSame(self::signer()->capturedDigest($first->toArray()), self::signer()->capturedDigest($later->toArray()));
    }

    /**
     * The clock is read once per record, as each record is finalised, never
     * when the finaliser is built.
     *
     * @return void
     */
    public function testReadsTheClockOncePerRecord(): void
    {
        $clock = new class implements Clock {
            /** @var int How many times the clock has been read. */
            public int $reads = 0;

            /**
             * The instant, a microsecond later on each read.
             *
             * @return \Carbon\CarbonImmutable
             *
             * @throws \LogicException
             */
            #[\Override]
            public function now(): CarbonImmutable
            {
                $this->reads++;

                $instant = CarbonImmutable::createFromFormat('Y-m-d H:i:s.u', sprintf('2026-11-01 12:00:01.%06d', $this->reads), 'UTC');

                return $instant ?: throw new \LogicException('The instant is malformed.');
            }
        };

        $finaliser = self::finaliser($clock);

        self::assertSame(0, $clock->reads);
        self::assertSame('2026-11-01T12:00:01.000001Z', $finaliser->finalise(self::record())->recordedAt);
        self::assertSame('2026-11-01T12:00:01.000002Z', $finaliser->finalise(self::record())->recordedAt);
        self::assertSame(2, $clock->reads);
    }

    /**
     * A ring whose current key it does not hold refuses to sign, and the
     * finaliser lets the settings' refusal propagate.
     *
     * @return void
     */
    public function testARingThatCannotSignPropagates(): void
    {
        $ring = new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => ['keys' => ['k2026' => self::SECRET], 'current' => 'k2027']]])));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.integrity.current` must name a key in `audit-log.integrity.keys`.');

        (new RecordFinaliser(FrozenClock::at('2026-11-01 12:00:01'), new RecordSigner($ring)))->finalise(self::record());
    }

    /**
     * A captured record of an approved invoice, under the pinned id.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function record(): AuditRecord
    {
        return RecordFactory::captured(id: self::ID);
    }

    /**
     * A finaliser on the clock, signing under the explicit ring.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @return \SineMacula\Laravel\AuditLog\Records\RecordFinaliser
     */
    private static function finaliser(Clock $clock): RecordFinaliser
    {
        return new RecordFinaliser($clock, self::signer());
    }

    /**
     * A clock stopped at the instant, in whatever time zone the instant has.
     *
     * @param  \Carbon\CarbonImmutable|false  $instant
     * @return \SineMacula\Laravel\AuditLog\Contracts\Clock
     */
    private static function clock(CarbonImmutable|false $instant): Clock
    {
        self::assertInstanceOf(CarbonImmutable::class, $instant);

        return new readonly class ($instant) implements Clock {
            /**
             * Constructor.
             *
             * @param  \Carbon\CarbonImmutable  $instant
             */
            public function __construct(

                /** The instant, in its own time zone. */
                private CarbonImmutable $instant,
            ) {}

            /**
             * The instant, in its own time zone.
             *
             * @return \Carbon\CarbonImmutable
             */
            #[\Override]
            public function now(): CarbonImmutable
            {
                return $this->instant;
            }
        };
    }

    /**
     * A signer over the explicit ring whose one key, `k2026`, signs.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\RecordSigner
     */
    private static function signer(): RecordSigner
    {
        return new RecordSigner(new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => ['keys' => ['k2026' => self::SECRET], 'current' => 'k2026']]]))));
    }
}
