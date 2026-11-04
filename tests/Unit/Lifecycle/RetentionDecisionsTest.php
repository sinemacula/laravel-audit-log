<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the decisions of one prune: the policy asked once per pair and
 * the same decision kept for the run, the cut-off at the run's UTC midnight
 * less the days kept, an entry exactly at the cut-off kept, a pair kept forever
 * admitting nothing, the answers and versions refused, naming the policy and
 * never the pair, and the decisions listed in the order made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RetentionDecisions::class)]
final class RetentionDecisionsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string An instant of the run's day, in another time zone than UTC. */
    private const string NOW = '2026-11-04T13:45:12.345678+02:00';

    /** @var string The run's midnight. */
    private const string MIDNIGHT = '2026-11-04T00:00:00.000000Z';

    /** @var string The refusal of a malformed answer, by the policy's class, the method and what the answer must be. */
    private const string MALFORMED = 'The retention policy `%s` answered `%s()` with %s; pruning refuses it.';

    /**
     * The policy is asked once for each distinct category and tenant pair,
     * however often the pair is asked for, and an equal tenant built again is
     * the same pair; a tenant of another type or id, or none, is another.
     *
     * @return void
     */
    public function testThePolicyIsAskedOncePerPair(): void
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $pairs = [
            ['general', null],
            ['general', Reference::of('team', 1)],
            ['general', Reference::of('team', 2)],
            ['general', Reference::of('group', 1)],
            ['security', Reference::of('team', 1)],
            ['security', null],
        ];

        foreach ($pairs as [$category, $tenant]) {
            $policy->shouldReceive('retainFor')->once()->withArgs(self::pair($category, $tenant))->andReturn(30);
            $policy->shouldReceive('preserveFor')->once()->withArgs(self::pair($category, $tenant))->andReturnNull();
        }

        $decisions = self::decisions($policy);

        foreach ([1, 2, 3] as $round) {
            foreach ($pairs as [$category, $tenant]) {
                $copy     = $tenant === null ? null : Reference::of($tenant->type, $tenant->id);
                $decision = $decisions->for($category, $copy);

                self::assertSame($decisions->for($category, $tenant), $decision, "round {$round}");
                self::assertSame($category, $decision->category);
            }
        }

        self::assertCount(count($pairs), $decisions->all());
    }

    /**
     * A tenant whose type and id would run together if joined is still its own
     * pair: protects against a memo key built by joining the parts.
     *
     * @return void
     */
    public function testAPairIsKeyedByEachPartApart(): void
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $policy->shouldReceive('retainFor')->times(3)->andReturn(1, 2, 3);
        $policy->shouldReceive('preserveFor')->times(3)->andReturnNull();

        $decisions = self::decisions($policy);

        self::assertSame(1, $decisions->for('general', Reference::of('a', 'b c'))->retainDays);
        self::assertSame(2, $decisions->for('general', Reference::of('a b', 'c'))->retainDays);
        self::assertSame(3, $decisions->for('general_a', Reference::of('b', 'c'))->retainDays);
        self::assertSame(1, $decisions->for('general', Reference::of('a', 'b c'))->retainDays);
    }

    /**
     * The cut-off is the UTC midnight that starts the run's day, whatever the
     * time zone or the hour of the instant given, less the days kept, as an
     * instant in the package's form.
     *
     * @return void
     */
    public function testTheCutoffIsMidnightLessTheDays(): void
    {
        $rows = [
            [self::NOW, 30, '2026-10-05T00:00:00.000000Z'],
            [self::NOW, 1, '2026-11-03T00:00:00.000000Z'],
            [self::NOW, 365, '2025-11-04T00:00:00.000000Z'],
            [self::NOW, 36500, '1926-11-29T00:00:00.000000Z'],
            ['2026-11-04T01:00:00.000000+05:00', 1, '2026-11-02T00:00:00.000000Z'],
            ['2026-11-04T23:59:59.999999Z', 1, '2026-11-03T00:00:00.000000Z'],
            ['2028-03-01T00:00:00.000000Z', 1, '2028-02-29T00:00:00.000000Z'],
            ['2026-03-30T12:00:00.000000+01:00', 2, '2026-03-28T00:00:00.000000Z'],
        ];

        foreach ($rows as [$now, $days, $cutoff]) {
            $decisions = self::decisions(self::answering($days, null), $now);

            self::assertSame($cutoff, $decisions->for('general', null)->cutoff, "{$now} less {$days} days");
        }

        self::assertSame(self::MIDNIGHT, self::decisions(self::answering(30, null))->midnight());
        self::assertSame('2026-11-03T00:00:00.000000Z', self::decisions(self::answering(30, null), '2026-11-04T01:00:00.000000+05:00')->midnight());
    }

    /**
     * An entry one microsecond before the cut-off is past its retention, and
     * one at the cut-off or a microsecond after it is not.
     *
     * @return void
     */
    public function testOneMicrosecondEitherSideOfTheCutoff(): void
    {
        $decision = self::decisions(self::answering(30, null))->for('general', null);

        self::assertSame('2026-10-05T00:00:00.000000Z', $decision->cutoff);
        self::assertTrue($decision->admits('2026-10-04T23:59:59.999999Z'));
        self::assertFalse($decision->admits('2026-10-05T00:00:00.000000Z'));
        self::assertFalse($decision->admits('2026-10-05T00:00:00.000001Z'));
    }

    /**
     * A pair kept forever has no cut-off and admits nothing, however old.
     *
     * @return void
     */
    public function testForeverAdmitsNothing(): void
    {
        $decision = self::decisions(self::answering(null, PHP_INT_MAX))->for('general', null);

        self::assertNull($decision->retainDays);
        self::assertSame(PHP_INT_MAX, $decision->preserveDays);
        self::assertNull($decision->cutoff);
        self::assertFalse($decision->admits('0001-01-01T00:00:00.000000Z'));
    }

    /**
     * Rows of `[retention, preservation]`: answers at each bound of each range.
     *
     * @return iterable<string, array{0: ?int, 1: ?int}>
     */
    public static function provideAnswersInRange(): iterable
    {
        yield from [
            'one day, no obligation'         => [1, null],
            'a hundred years, no obligation' => [36500, null],
            'one day preserved one day'      => [1, 1],
            'a hundred years preserved as'   => [36500, 36500],
            'forever, no obligation'         => [null, null],
            'forever, preserved forever'     => [null, PHP_INT_MAX],
            'forever, preserved a day'       => [null, 1],
            'forever, preserved a century'   => [null, 36500],
            'longer than preserved'          => [365, 30],
        ];
    }

    /**
     * Each answer within its range is kept as given.
     *
     * @param  ?int  $retainDays
     * @param  ?int  $preserveDays
     * @return void
     */
    #[DataProvider('provideAnswersInRange')]
    public function testAcceptsAnAnswerInRange(?int $retainDays, ?int $preserveDays): void
    {
        $decision = self::decisions(self::answering($retainDays, $preserveDays))->for('general', null);

        self::assertSame($retainDays, $decision->retainDays);
        self::assertSame($preserveDays, $decision->preserveDays);
    }

    /**
     * Rows of `[method, answer]`: answers outside the range of the method.
     *
     * @return iterable<string, array{0: 'preserveFor'|'retainFor', 1: int}>
     */
    public static function provideAnswersOutOfRange(): iterable
    {
        yield from [
            'a retention of zero days'              => ['retainFor', 0],
            'a retention one day over a century'    => ['retainFor', 36501],
            'a negative retention'                  => ['retainFor', -1],
            'a retention of PHP_INT_MAX'            => ['retainFor', PHP_INT_MAX],
            'a preservation of zero days'           => ['preserveFor', 0],
            'a preservation one day over a century' => ['preserveFor', 36501],
            'a negative preservation'               => ['preserveFor', -1],
            'a preservation one short of forever'   => ['preserveFor', PHP_INT_MAX - 1],
        ];
    }

    /**
     * An answer outside its range is refused, naming the policy's class and the
     * method, and makes no decision.
     *
     * @param  'preserveFor'|'retainFor'  $method
     * @param  int  $answer
     * @return void
     */
    #[DataProvider('provideAnswersOutOfRange')]
    public function testRefusesAnAnswerOutOfRange(string $method, int $answer): void
    {
        $policy    = $method === 'retainFor' ? self::answering($answer, null) : self::answering(null, $answer);
        $decisions = self::decisions($policy);
        $grammar   = $method === 'retainFor' ? 'something other than 1 to 36500 days or null' : 'something other than 1 to 36500 days, PHP_INT_MAX or null';

        try {
            $decisions->for('general', null);

            self::fail('Expected the answer to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertNotInstanceOf(RetentionConflictException::class, $exception);
            self::assertSame(sprintf(self::MALFORMED, $policy::class, $method, $grammar), $exception->getMessage());
        }

        self::assertSame([], $decisions->all());
    }

    /**
     * A finite retention shorter than its preservation, a preservation forever
     * among them, is refused with a conflict and makes no decision; one as long
     * as its preservation is kept.
     *
     * @return void
     */
    public function testRefusesARetentionShorterThanAPreservation(): void
    {
        foreach ([[30, 31], [1, 36500], [36500, PHP_INT_MAX]] as [$retainDays, $preserveDays]) {
            $policy    = self::answering($retainDays, $preserveDays);
            $decisions = self::decisions($policy);

            try {
                $decisions->for('general', null);

                self::fail("Expected {$retainDays} days kept for {$preserveDays} preserved to be refused.");
            } catch (RetentionConflictException $exception) {
                self::assertSame(RetentionConflictException::forPolicy($policy::class)->getMessage(), $exception->getMessage());
            }

            self::assertSame([], $decisions->all());
        }

        self::assertSame(30, self::decisions(self::answering(30, 30))->for('general', null)->retainDays);
    }

    /**
     * Neither a conflict nor a malformed answer names the category or the
     * tenant it was asked for.
     *
     * @return void
     */
    public function testTheRefusalNamesNoCategoryOrTenant(): void
    {
        $tenant = Reference::of('organisation', 'acme-tenant-7');

        foreach ([self::answering(30, 31), self::answering(0, null), self::answering(null, 0)] as $policy) {
            try {
                self::decisions($policy)->for('restricted_category', $tenant);

                self::fail('Expected the answer to be refused.');
            } catch (\UnexpectedValueException $exception) {
                self::assertStringContainsString($policy::class, $exception->getMessage());
                self::assertStringNotContainsString('restricted_category', $exception->getMessage());
                self::assertStringNotContainsString('organisation', $exception->getMessage());
                self::assertStringNotContainsString('acme-tenant-7', $exception->getMessage());
            }
        }
    }

    /**
     * A version is asked once and kept, and one at the length bounds passes;
     * an empty one, one longer than 64 characters, one that is not clean text
     * and one that is not valid UTF-8 are refused, naming the policy.
     *
     * @return void
     */
    public function testRefusesAMalformedVersion(): void
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $policy->shouldReceive('version')->once()->andReturn('custom:v1');

        $decisions = self::decisions($policy);

        self::assertSame('custom:v1', $decisions->version());
        self::assertSame('custom:v1', $decisions->version());

        foreach (['a', str_repeat('é', 64)] as $version) {
            self::assertSame($version, self::decisions(self::versioned($version))->version());
        }

        foreach (['', str_repeat('a', 65), str_repeat('é', 65), "v1\n", "v1\u{202E}", "v1\x00", "v1\xC3"] as $version) {
            $policy = self::versioned($version);

            try {
                self::decisions($policy)->version();

                self::fail('Expected the version to be refused.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame(sprintf(self::MALFORMED, $policy::class, 'version', 'something other than 1 to 64 characters of clean text'), $exception->getMessage());
            }
        }
    }

    /**
     * Every decision is listed once, in the order its pair was first asked for,
     * and none before any is made.
     *
     * @return void
     */
    public function testAllListsEveryDecisionInOrder(): void
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $policy->shouldReceive('retainFor')->andReturnUsing(static fn (string $category): ?int => $category === 'audit' ? null : 30);
        $policy->shouldReceive('preserveFor')->andReturnNull();

        $decisions = self::decisions($policy);
        $tenant    = Reference::of('team', 1);

        $before = $decisions->all();

        self::assertSame([], $before);

        $decisions->for('security', $tenant);
        $decisions->for('audit', null);
        $decisions->for('security', $tenant);
        $decisions->for('access', null);
        $decisions->for('audit', null);

        self::assertSame([
            ['security', 'team', '1', 30, null, '2026-10-05T00:00:00.000000Z'],
            ['audit', null, null, null, null, null],
            ['access', null, null, 30, null, '2026-10-05T00:00:00.000000Z'],
        ], array_map(static fn (RetentionDecision $decision): array => $decision->toArray(), $decisions->all()));
    }

    /**
     * What the policy throws reaches the caller as it was, and the pair is
     * asked again the next time, since no decision was made.
     *
     * @return void
     */
    public function testWhatThePolicyThrowsPropagates(): void
    {
        $policy = \Mockery::mock(RetentionPolicy::class);
        $thrown = new \RuntimeException('The policy store is down.');

        $policy->shouldReceive('retainFor')->twice()->andThrow($thrown);
        $policy->shouldNotReceive('preserveFor');

        $decisions = self::decisions($policy);

        foreach ([1, 2] as $attempt) {
            try {
                $decisions->for('general', null);

                self::fail('Expected the policy\'s exception.');
            } catch (\RuntimeException $exception) {
                self::assertSame($thrown, $exception, "attempt {$attempt}");
            }
        }

        self::assertSame([], $decisions->all());
    }

    /**
     * A matcher of the arguments of a call for the pair.
     *
     * @param  string  $category
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @return \Closure(string, ?\SineMacula\Laravel\AuditLog\Records\Reference): bool
     */
    private static function pair(string $category, ?Reference $tenant): \Closure
    {
        return static fn (string $asked, ?Reference $of): bool => $asked === $category
            && ($tenant === null ? $of === null : $of !== null && $of->equals($tenant));
    }

    /**
     * A policy that answers every pair with the retention and preservation
     * given.
     *
     * @param  ?int  $retainDays
     * @param  ?int  $preserveDays
     * @return \Mockery\MockInterface&\SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy
     */
    private static function answering(?int $retainDays, ?int $preserveDays): MockInterface&RetentionPolicy
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $policy->shouldReceive('retainFor')->andReturn($retainDays);
        $policy->shouldReceive('preserveFor')->andReturn($preserveDays);

        return $policy;
    }

    /**
     * A policy whose version is the one given.
     *
     * @param  string  $version
     * @return \Mockery\MockInterface&\SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy
     */
    private static function versioned(string $version): MockInterface&RetentionPolicy
    {
        $policy = \Mockery::mock(RetentionPolicy::class);

        $policy->shouldReceive('version')->andReturn($version);

        return $policy;
    }

    /**
     * The decisions of a run over the policy, on the day of the instant.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy  $policy
     * @param  string  $now
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions
     */
    private static function decisions(RetentionPolicy $policy, string $now = self::NOW): RetentionDecisions
    {
        $instant = \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.uP', $now) ?: self::fail(sprintf('%s is no instant.', $now));

        return new RetentionDecisions($policy, $instant);
    }
}
