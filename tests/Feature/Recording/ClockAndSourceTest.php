<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * End-to-end tests for what a record takes from the bound clock and the source
 * settings, read back from the database: the time it occurred, the time its id
 * embeds, one UTC instant whatever zone the clock answers in, and its source.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(SourceSettings::class)]
final class ClockAndSourceTest extends TestCase
{
    /** @var string The code the tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The instant the clock is frozen at, as it is stored. */
    private const string INSTANT = '2026-07-01T12:00:00.123456Z';

    /**
     * The bound clock gives the time the activity occurred, to the microsecond,
     * and the time it was recorded.
     *
     * @return void
     */
    public function testAFrozenClockGivesOccurredAt(): void
    {
        $this->app?->instance(Clock::class, FrozenClock::at(self::INSTANT));

        AuditLog::record(self::CODE);

        $entry = AuditEntry::query()->sole();

        self::assertSame(self::INSTANT, StoredTime::format($entry->occurred_at));
        self::assertSame(self::INSTANT, StoredTime::format($entry->recorded_at));
    }

    /**
     * The id is a UUID v7 whose time is the clock's, in milliseconds.
     *
     * @return void
     */
    public function testTheIdEmbedsTheClockTime(): void
    {
        $this->app?->instance(Clock::class, FrozenClock::at(self::INSTANT));

        $id = AuditLog::record(self::CODE)->id;

        self::assertSame('7', $id[14]);
        self::assertSame(
            CarbonImmutable::parse(self::INSTANT)->getTimestampMs(),
            hexdec(substr(str_replace('-', '', $id), 0, 12)),
        );
        self::assertSame($id, AuditEntry::query()->sole()->id);
    }

    /**
     * A clock that answers in another zone stores the same UTC instant.
     *
     * @return void
     */
    public function testAPacificInstantStoresAsTheSameUtcInstant(): void
    {
        $this->app?->instance(Clock::class, new class implements Clock {
            /**
             * The instant, in Pacific Daylight Time.
             *
             * @return \Carbon\CarbonImmutable
             */
            #[\Override]
            public function now(): CarbonImmutable
            {
                return new CarbonImmutable('2026-07-01 05:00:00.123456', 'America/Los_Angeles');
            }
        });

        AuditLog::record(self::CODE);

        $entry = AuditEntry::query()->sole();

        self::assertSame(self::INSTANT, StoredTime::format($entry->occurred_at));
        self::assertSame(self::INSTANT, StoredTime::format($entry->recorded_at));
    }

    /**
     * With no source configured, the source is a slug of the application's name
     * and there is no region.
     *
     * @return void
     */
    public function testTheSourceDefaultsToASlugOfTheApplicationName(): void
    {
        app(ConfigRepository::class)->set('app.name', 'Acme Billing');

        AuditLog::record(self::CODE);

        $entry = AuditEntry::query()->sole();

        self::assertSame('acme-billing', $entry->source_id);
        self::assertNull($entry->source_region);
    }

    /**
     * A configured source and region are stored as given, never slugged.
     *
     * @return void
     */
    public function testAConfiguredSourceIsStored(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.source.id', 'Billing/EU West');
        $config->set('audit-log.source.region', 'eu-west-1');

        AuditLog::record(self::CODE);

        $entry = AuditEntry::query()->sole();

        self::assertSame('Billing/EU West', $entry->source_id);
        self::assertSame('eu-west-1', $entry->source_region);
    }

    /**
     * An application name that gives no slug, with no source configured, fails
     * closed naming the setting, and nothing is written.
     *
     * @return void
     */
    public function testAnEmptySlugFailsClosed(): void
    {
        app(ConfigRepository::class)->set('app.name', '!!!');

        try {
            app(Recorder::class)->record(self::CODE);

            self::fail('Expected the source to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('`audit-log.source.id` must be set, because `app.name` gives no slug.', $exception->getMessage());
        }

        self::assertSame(0, AuditEntry::query()->count());
    }
}
