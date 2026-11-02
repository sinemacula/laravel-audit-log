<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Concerns;

use Illuminate\Container\Container;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\Concerns\InteractsWithAuditLog;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;
use Tests\Unit\Stubs\Enums\StubActivity;

/**
 * Feature tests for the assertions a test makes on the audit log: when each
 * passes and fails, what a failure says, and that asserting without the fake
 * fails rather than reads the real store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(InteractsWithAuditLog::class)]
final class InteractsWithAuditLogTest extends TestCase
{
    use InteractsWithAuditLog, InteractsWithAuditStore;

    /** @var string A property value no failure message may ever print. */
    private const string SECRET = 'a-value-only-the-record-holds';

    /**
     * A record of the code passes.
     *
     * @return void
     */
    public function testAssertAuditedPassesWhenTheCodeWasRecorded(): void
    {
        $this->stored('invoice.approved');

        $this->assertAudited('invoice.approved');
    }

    /**
     * No record of the code fails, naming the code and what was stored.
     *
     * @return void
     */
    public function testAssertAuditedFailsWhenItWasNot(): void
    {
        $this->stored('invoice.sent');

        self::assertStringContainsString(
            'Expected a record of [invoice.approved]. Stored, in order: invoice.sent.',
            $this->failureOf(fn () => $this->assertAudited('invoice.approved')),
        );
    }

    /**
     * The closure sees the captured record of the code, and one it accepts
     * passes.
     *
     * @return void
     */
    public function testAssertAuditedHonoursTheClosure(): void
    {
        $this->stored('invoice.sent');
        $this->stored('invoice.approved');

        $seen = [];

        $this->assertAudited('invoice.approved', static function (AuditRecord $record) use (&$seen): bool {
            $seen[] = $record->event;

            return true;
        });

        self::assertSame(['invoice.approved'], $seen);
    }

    /**
     * A closure refusing every record of the code fails, and says so.
     *
     * @return void
     */
    public function testAssertAuditedFailsWhenTheClosureRefusesEveryRecord(): void
    {
        $this->stored('invoice.approved');

        self::assertStringContainsString(
            'Expected a record of [invoice.approved] that the closure accepts. Stored, in order: invoice.approved.',
            $this->failureOf(fn () => $this->assertAudited('invoice.approved', static fn (AuditRecord $record): bool => false)),
        );
    }

    /**
     * An enum case stands for its code in every assertion taking one.
     *
     * @return void
     */
    public function testAssertAuditedTakesAnEnum(): void
    {
        $this->stored('invoice.approved');

        $this->assertAudited(StubActivity::APPROVED);
        $this->assertAuditedTimes(StubActivity::APPROVED, 1);

        FakeAuditStore::fake();

        $this->assertNotAudited(StubActivity::APPROVED);
    }

    /**
     * A code `event()` would refuse is refused, so a mistyped code cannot pass.
     *
     * @return void
     */
    public function testAMalformedCodeIsRefused(): void
    {
        FakeAuditStore::fake();

        $this->expectException(\InvalidArgumentException::class);

        $this->assertNotAudited('Not A Code');
    }

    /**
     * No record of the code passes, another code notwithstanding.
     *
     * @return void
     */
    public function testAssertNotAuditedPassesWhenItWasNot(): void
    {
        $this->stored('invoice.sent');

        $this->assertNotAudited('invoice.approved');
    }

    /**
     * A record of the code fails, naming the code and what was stored.
     *
     * @return void
     */
    public function testAssertNotAuditedFailsWhenItWas(): void
    {
        $this->stored('invoice.approved');

        self::assertStringContainsString(
            'Expected no record of [invoice.approved]. Stored, in order: invoice.approved.',
            $this->failureOf(fn () => $this->assertNotAudited('invoice.approved')),
        );
    }

    /**
     * A record the closure refuses does not count, and one it accepts does.
     *
     * @return void
     */
    public function testAssertNotAuditedHonoursTheClosure(): void
    {
        $this->stored('invoice.approved');

        $this->assertNotAudited('invoice.approved', static fn (AuditRecord $record): bool => false);

        self::assertStringContainsString(
            'Expected no record of [invoice.approved] that the closure accepts. Stored, in order: invoice.approved.',
            $this->failureOf(fn () => $this->assertNotAudited('invoice.approved', static fn (AuditRecord $record): bool => true)),
        );
    }

    /**
     * An empty fake passes.
     *
     * @return void
     */
    public function testAssertNothingAuditedPassesWithNothing(): void
    {
        FakeAuditStore::fake();

        $this->assertNothingAudited();
    }

    /**
     * Any record fails.
     *
     * @return void
     */
    public function testAssertNothingAuditedFailsWithARecord(): void
    {
        $this->stored('invoice.approved');

        self::assertStringContainsString(
            'Expected no record. Stored, in order: invoice.approved.',
            $this->failureOf(fn () => $this->assertNothingAudited()),
        );
    }

    /**
     * Only records of the code are counted, and zero is a count.
     *
     * @return void
     */
    public function testAssertAuditedTimesPasses(): void
    {
        $this->stored('invoice.sent');
        $this->stored('invoice.approved');
        $this->stored('invoice.approved');

        $this->assertAuditedTimes('invoice.approved', 2);
        $this->assertAuditedTimes('invoice.sent', 1);
        $this->assertAuditedTimes('invoice.refunded', 0);
    }

    /**
     * Too few and too many both fail, each with both counts.
     *
     * @return void
     */
    public function testAssertAuditedTimesFails(): void
    {
        $this->stored('invoice.approved');
        $this->stored('invoice.approved');

        self::assertStringContainsString(
            'Expected 3 of [invoice.approved], and there were 2. Stored, in order: invoice.approved, invoice.approved.',
            $this->failureOf(fn () => $this->assertAuditedTimes('invoice.approved', 3)),
        );

        self::assertStringContainsString(
            'Expected 1 of [invoice.approved], and there were 2.',
            $this->failureOf(fn () => $this->assertAuditedTimes('invoice.approved', 1)),
        );
    }

    /**
     * Every assertion returns the test case, for chaining.
     *
     * @return void
     */
    public function testEveryAssertionReturnsTheTestCase(): void
    {
        $this->stored('invoice.approved');

        self::assertSame($this, $this->assertAudited('invoice.approved'));
        self::assertSame($this, $this->assertNotAudited('invoice.sent'));
        self::assertSame($this, $this->assertAuditedTimes('invoice.approved', 1));

        FakeAuditStore::fake();

        self::assertSame($this, $this->assertNothingAudited());
    }

    /**
     * Every assertion is public, as a framework's own are, so a helper holding
     * the test case can make it.
     *
     * @return void
     */
    public function testEveryAssertionIsCallableFromOutsideTheTestCase(): void
    {
        $this->stored('invoice.approved');

        $helper = new class {
            /**
             * Make every assertion on the test case.
             *
             * @param  \Tests\Feature\Testing\Concerns\InteractsWithAuditLogTest  $test
             * @return void
             */
            public function assertOn(InteractsWithAuditLogTest $test): void
            {
                $test->assertAudited('invoice.approved');
                $test->assertNotAudited('invoice.sent');
                $test->assertAuditedTimes('invoice.approved', 1);

                FakeAuditStore::fake();

                $test->assertNothingAudited();
            }
        };

        $helper->assertOn($this);
    }

    /**
     * A failure lists the codes stored, in the order stored; with none it says
     * so.
     *
     * @return void
     */
    public function testAFailureListsWhatWasRecorded(): void
    {
        FakeAuditStore::fake();

        self::assertStringContainsString(
            'Expected a record of [invoice.approved]. No record was stored.',
            $this->failureOf(fn () => $this->assertAudited('invoice.approved')),
        );

        $this->stored('invoice.sent');
        $this->stored('invoice.refunded');

        self::assertStringContainsString(
            'Stored, in order: invoice.sent, invoice.refunded.',
            $this->failureOf(fn () => $this->assertAudited('invoice.approved')),
        );
    }

    /**
     * No failure prints a property, since a failure message is printed to a
     * build's log.
     *
     * @return void
     */
    public function testAFailureNamesNoProperty(): void
    {
        $this->stored('invoice.approved', ['token' => self::SECRET]);

        $failures = [
            $this->failureOf(fn () => $this->assertAudited('invoice.sent')),
            $this->failureOf(fn () => $this->assertAudited('invoice.approved', static fn (AuditRecord $record): bool => false)),
            $this->failureOf(fn () => $this->assertNotAudited('invoice.approved')),
            $this->failureOf(fn () => $this->assertNothingAudited()),
            $this->failureOf(fn () => $this->assertAuditedTimes('invoice.approved', 2)),
        ];

        foreach ($failures as $failure) {
            self::assertStringNotContainsString(self::SECRET, $failure);
            self::assertStringNotContainsString('token', $failure);
        }
    }

    /**
     * With the real store bound, every assertion fails asking for the fake.
     *
     * @return void
     */
    public function testAssertingWithoutAFakeFails(): void
    {
        $assertions = [
            fn () => $this->assertAudited('invoice.approved'),
            fn () => $this->assertNotAudited('invoice.approved'),
            fn () => $this->assertNothingAudited(),
            fn () => $this->assertAuditedTimes('invoice.approved', 0),
        ];

        foreach ($assertions as $assertion) {
            self::assertStringContainsString('Call `AuditLog::fake()` before asserting on the audit log.', $this->failureOf($assertion));
        }
    }

    /**
     * With no store bound at all, the assertion fails asking for the fake
     * rather than with a container error.
     *
     * @return void
     */
    public function testAssertingWithNoStoreBoundFails(): void
    {
        $application = Container::getInstance();

        Container::setInstance(new Container);

        try {
            $failure = $this->failureOf(fn () => $this->assertNothingAudited());
        } finally {
            Container::setInstance($application);
        }

        self::assertStringContainsString('Call `AuditLog::fake()` before asserting on the audit log.', $failure);
    }

    /**
     * Store a record of the code in the fake, binding one the first time.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $code
     * @param  array<array-key, mixed>  $properties
     * @return void
     */
    private function stored(string $code, array $properties = []): void
    {
        $store = app(AuditStore::class);
        $fake  = $store instanceof FakeAuditStore ? $store : FakeAuditStore::fake();

        $fake->store($this->finaliser()->finalise(RecordFactory::withFields(['event' => $code], RecordFactory::captured($properties))));
    }

    /**
     * The message of the failure the assertion must raise.
     *
     * @param  \Closure(): self  $assertion
     * @return string
     */
    private function failureOf(\Closure $assertion): string
    {
        try {
            $assertion();
        } catch (AssertionFailedError $failure) {
            return $failure->getMessage();
        }

        self::fail('Expected the assertion to fail.');
    }
}
