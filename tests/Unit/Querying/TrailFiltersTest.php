<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Unit\Stubs\Enums\StubActivity;

/**
 * Unit tests for a caller's filters on a read of the trail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailFilters::class)]
final class TrailFiltersTest extends TestCase
{
    /** @var string A value no refusal may name. */
    private const string SECRET = 'SECRET-VALUE-42';

    /**
     * Filters made from nothing narrow nothing.
     *
     * @return void
     */
    public function testNoneFiltersNothing(): void
    {
        $filters = TrailFilters::none();

        self::assertNull($filters->actor);
        self::assertNull($filters->subject);
        self::assertNull($filters->principal);
        self::assertNull($filters->tenant);
        self::assertSame([], $filters->events);
        self::assertNull($filters->eventPrefix);
        self::assertSame([], $filters->categories);
        self::assertSame([], $filters->outcomes);
        self::assertNull($filters->from);
        self::assertNull($filters->to);
        self::assertNull($filters->correlationId);
        self::assertNull($filters->holding);
        self::assertNull($filters->normalised()['holding_data_of']);
    }

    /**
     * Each dimension replaces only itself, leaving the original unchanged.
     *
     * @return void
     */
    public function testEachDimensionReplacesItself(): void
    {
        $first = TrailFilters::none()
            ->withReference('actor', Reference::of('user', '1'))
            ->withReference('subject', Reference::of('invoice', '1'))
            ->withReference('principal', Reference::of('service', '1'))
            ->withReference('tenant', Reference::of('team', '1'))
            ->withEvents(['invoice.approved'])
            ->withCategories(['billing'])
            ->withOutcomes([Outcome::SUCCESS])
            ->withWindow(new \DateTimeImmutable('2026-11-01T00:00:00Z'), new \DateTimeImmutable('2026-11-02T00:00:00Z'))
            ->withCorrelation('app:one')
            ->withHoldingDataOf(Reference::of('user', '1'));

        $second = $first
            ->withReference('actor', Reference::of('user', '2'))
            ->withReference('subject', Reference::of('invoice', '2'))
            ->withReference('principal', Reference::of('service', '2'))
            ->withReference('tenant', Reference::of('team', '2'))
            ->withEvents(['invoice.voided'])
            ->withCategories(['auth'])
            ->withOutcomes([Outcome::DENIED])
            ->withWindow(new \DateTimeImmutable('2026-12-01T00:00:00Z'), null)
            ->withCorrelation('app:two')
            ->withHoldingDataOf(Reference::of('user', '2'));

        self::assertSame([
            'actor'           => ['user', '2'],
            'categories'      => ['auth'],
            'correlation_id'  => 'app:two',
            'event_prefix'    => null,
            'events'          => ['invoice.voided'],
            'from'            => '2026-12-01T00:00:00.000000Z',
            'holding_data_of' => ['user', '2'],
            'outcomes'        => ['denied'],
            'principal'       => ['service', '2'],
            'subject'         => ['invoice', '2'],
            'tenant'          => ['team', '2'],
            'to'              => null,
        ], $second->normalised());

        self::assertSame(['user', '1'], $first->normalised()['actor']);
        self::assertSame('app:one', $first->correlationId);
        self::assertSame(['user', '1'], $first->normalised()['holding_data_of']);

        $actorOnly = TrailFilters::none()->withReference('actor', Reference::of('user', '1'));

        self::assertSame(['user', '1'], $actorOnly->normalised()['actor']);
        self::assertNull($actorOnly->subject);
        self::assertNull($actorOnly->principal);
        self::assertNull($actorOnly->tenant);
    }

    /**
     * A reference filter is on the actor, subject, principal or tenant only.
     *
     * @return void
     */
    public function testRefusesAnUnknownReferenceDimension(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reference filter must be on the actor, the subject, the principal or the tenant.');

        TrailFilters::none()->withReference('owner', Reference::of('user', '1'));
    }

    /**
     * Codes, as strings or backed cases, are validated, unique and sorted.
     *
     * @return void
     */
    public function testCodesAreValidatedSortedAndDeduplicated(): void
    {
        $filters = TrailFilters::none()->withEvents(['invoice.voided', 'invoice.approved', 'invoice.voided', StubActivity::APPROVED]);

        self::assertSame(['invoice.approved', 'invoice.voided'], $filters->events);

        foreach (['invoice', 'Invoice.approved', 'invoice..approved', '', 'a.' . str_repeat('b', 190)] as $code) {
            try {
                TrailFilters::none()->withEvents(['invoice.approved', $code]);

                self::fail('Expected the code to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An event filter\'s codes must each be lower-case dotted segments of at most 191 bytes, such as `invoice.approved`.', $exception->getMessage());
            }
        }
    }

    /**
     * A reserved code is accepted, since reads may look for the package's own.
     *
     * @return void
     */
    public function testAReservedCodeIsAccepted(): void
    {
        self::assertSame(['audit_log.trail_read'], TrailFilters::none()->withEvents(['audit_log.trail_read'])->events);
    }

    /**
     * Fifty codes are held; fifty-one or none are refused, naming the limit.
     *
     * @return void
     */
    public function testRefusesMoreThanFiftyCodes(): void
    {
        $fifty = array_map(static fn (int $index): string => "app.code_{$index}", range(1, TrailFilters::MAX_CODES));

        self::assertCount(50, TrailFilters::none()->withEvents([...$fifty, ...$fifty])->events);

        foreach ([[...$fifty, 'app.one_more'], []] as $codes) {
            try {
                TrailFilters::none()->withEvents($codes);

                self::fail('Expected the codes to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An event filter must hold from 1 to 50 codes.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[prefix]`: not dotted lower-case segments, or too long.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedPrefixes(): iterable
    {
        yield from [
            'no trailing dot'      => ['authentication'],
            'a leading dot'        => ['.a.'],
            'upper case'           => ['A.'],
            'an empty segment'     => ['a..'],
            'a whole code'         => ['a.b'],
            'empty'                => [''],
            'a lone dot'           => ['.'],
            'a wildcard'           => ['a%.'],
            'a trailing line feed' => ["a.\n"],
            '191 bytes'            => [str_repeat('a', 190) . '.'],
        ];
    }

    /**
     * A prefix that is not dotted or longer than 190 bytes is refused.
     *
     * @param  string  $prefix
     * @return void
     */
    #[DataProvider('provideMalformedPrefixes')]
    public function testRefusesAPrefixThatIsNotDotted(string $prefix): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An event prefix filter must be lower-case dotted segments ending in a dot, such as `invoice.`, of at most 190 bytes.');

        TrailFilters::none()->withEventPrefix($prefix);
    }

    /**
     * Dotted prefixes up to 190 bytes are accepted.
     *
     * @return void
     */
    public function testAcceptsADottedPrefix(): void
    {
        foreach (['app.', 'app.a_b.', 'audit_log.', 'a1.b2.c3.', str_repeat('a', 189) . '.'] as $prefix) {
            self::assertSame($prefix, TrailFilters::none()->withEventPrefix($prefix)->eventPrefix);
        }
    }

    /**
     * Codes and a prefix are one dimension, so either replaces the other.
     *
     * @return void
     */
    public function testAPrefixAndCodesReplaceEachOther(): void
    {
        $prefixed = TrailFilters::none()->withEvents(['invoice.approved'])->withEventPrefix('invoice.');

        self::assertSame([], $prefixed->events);
        self::assertSame('invoice.', $prefixed->eventPrefix);

        $coded = $prefixed->withEvents(['invoice.voided']);

        self::assertSame(['invoice.voided'], $coded->events);
        self::assertNull($coded->eventPrefix);
    }

    /**
     * A window ending at or before its start is refused; `null` ends clear it.
     *
     * @return void
     */
    public function testRefusesAnEmptyOrBackwardWindow(): void
    {
        $at     = new \DateTimeImmutable('2026-11-01T12:00:00.000001Z');
        $before = new \DateTimeImmutable('2026-11-01T12:00:00Z');

        foreach ([[$at, $at], [$at, $before], [new \DateTimeImmutable('2026-11-01T13:00:00.000001+01:00'), $at]] as [$from, $to]) {
            try {
                TrailFilters::none()->withWindow($from, $to);

                self::fail('Expected the window to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A time window filter must end after it starts.', $exception->getMessage());
            }
        }

        $windowed = TrailFilters::none()->withWindow($before, $at);

        self::assertSame('2026-11-01T12:00:00.000000Z', $windowed->from);
        self::assertSame('2026-11-01T12:00:00.000001Z', $windowed->to);

        $cleared = $windowed->withWindow(null, null);

        self::assertNull($cleared->from);
        self::assertNull($cleared->to);
        self::assertNull(TrailFilters::none()->withWindow($at, null)->to);
        self::assertNull(TrailFilters::none()->withWindow(null, $at)->from);
    }

    /**
     * Each window end is converted to UTC, keeping its microseconds.
     *
     * @return void
     */
    public function testTheWindowIsUtcToTheMicrosecond(): void
    {
        $filters = TrailFilters::none()->withWindow(
            new \DateTimeImmutable('2026-11-01T13:00:00.123456', new \DateTimeZone('Europe/Paris')),
            new \DateTimeImmutable('2026-11-01T07:00:00.654321', new \DateTimeZone('America/New_York')),
        );

        self::assertSame('2026-11-01T12:00:00.123456Z', $filters->from);
        self::assertSame('2026-11-01T12:00:00.654321Z', $filters->to);
    }

    /**
     * Rows of `[correlation id]`: ids the builder refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedCorrelationIds(): iterable
    {
        yield from [
            'no namespace'         => ['ticket-123'],
            'an empty value'       => ['app:'],
            'a space first'        => ['app: x'],
            'upper case namespace' => ['App:x'],
            'a control character'  => ["app:x\u{7}"],
            'a line feed'          => ["app:x\n"],
            'longer than 191'      => ['app:' . str_repeat('x', 188)],
            'a namespace too long' => [str_repeat('a', 33) . ':x'],
            'empty'                => [''],
            'invalid utf-8'        => ["app:\xFF"],
            'a namespace digit'    => ['1app:x'],
        ];
    }

    /**
     * A correlation id the builder refuses is refused by the filter too.
     *
     * @param  string  $correlationId
     * @return void
     */
    #[DataProvider('provideMalformedCorrelationIds')]
    public function testRefusesAMalformedCorrelationId(string $correlationId): void
    {
        try {
            (new PendingRecord)->correlatedWith($correlationId);

            self::fail('Expected the builder to refuse the id.');
        } catch (\InvalidArgumentException) {
            // The builder refuses it, as the filter must
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A correlation filter must be namespaced, as `<namespace>:<value>`, and from 1 to 191 characters with no control characters.');

        TrailFilters::none()->withCorrelation($correlationId);
    }

    /**
     * A correlation id the builder accepts is accepted as given.
     *
     * @return void
     */
    public function testAcceptsWhatTheBuilderAccepts(): void
    {
        foreach (['app:ticket-123', 'a:x', 'job_run-1:Ünïcode value', 'app:' . str_repeat('x', 187), str_repeat('a', 32) . ':x'] as $correlationId) {
            (new PendingRecord)->correlatedWith($correlationId);

            self::assertSame($correlationId, TrailFilters::none()->withCorrelation($correlationId)->correlationId);
        }
    }

    /**
     * Categories are validated, deduplicated and sorted, from one to fifty.
     *
     * @return void
     */
    public function testCategoriesAreValidatedSortedAndDeduplicated(): void
    {
        self::assertSame(['auth', 'billing'], TrailFilters::none()->withCategories(['billing', 'auth', 'billing'])->categories);

        $fifty = array_map(static fn (int $index): string => "category_{$index}", range(1, TrailFilters::MAX_CATEGORIES));

        self::assertCount(50, TrailFilters::none()->withCategories($fifty)->categories);

        $refusals = [
            'A category filter must hold from 1 to 50 categories.'                                                                    => [[...$fifty, 'one_more'], []],
            'A category filter\'s categories must each be 1 to 64 lower-case letters, digits or underscores, starting with a letter.' => [['Billing'], ['billing', ''], ['1a']],
        ];

        foreach ($refusals as $message => $lists) {
            foreach ($lists as $categories) {
                try {
                    TrailFilters::none()->withCategories($categories);

                    self::fail('Expected the categories to be refused.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame($message, $exception->getMessage());
                }
            }
        }
    }

    /**
     * Outcomes are deduplicated and sorted, and at least one is needed.
     *
     * @return void
     */
    public function testOutcomesAreDeduplicatedAndNeverEmpty(): void
    {
        self::assertSame(['denied', 'success'], TrailFilters::none()->withOutcomes([Outcome::SUCCESS, Outcome::DENIED, Outcome::SUCCESS])->outcomes);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An outcome filter must hold at least one outcome.');

        TrailFilters::none()->withOutcomes([]);
    }

    /**
     * The normalised form and its canonical encoding ignore input order.
     *
     * @return void
     */
    public function testTheNormalisedForm(): void
    {
        $none = '{"actor":null,"categories":[],"correlation_id":null,"event_prefix":null,"events":[],"from":null,"holding_data_of":null,"outcomes":[],'
            . '"principal":null,"subject":null,"tenant":null,"to":null}';

        self::assertSame($none, CanonicalEncoder::encode(TrailFilters::none()->normalised()));
        self::assertSame(
            ['actor', 'categories', 'correlation_id', 'event_prefix', 'events', 'from', 'holding_data_of', 'outcomes', 'principal', 'subject', 'tenant', 'to'],
            array_keys(TrailFilters::none()->normalised()),
        );

        $filters = TrailFilters::none()
            ->withReference('tenant', Reference::of('team', '7'))
            ->withEventPrefix('invoice.')
            ->withOutcomes([Outcome::SUCCESS, Outcome::FAILURE])
            ->withWindow(new \DateTimeImmutable('2026-11-01T00:00:00Z'), null)
            ->withHoldingDataOf(Reference::of('App\Models\User', '42'));

        $text = '{"actor":null,"categories":[],"correlation_id":null,"event_prefix":"invoice.","events":[],"from":"2026-11-01T00:00:00.000000Z",'
            . '"holding_data_of":["App\\\Models\\\User","42"],"outcomes":["failure","success"],"principal":null,"subject":null,"tenant":["team","7"],"to":null}';

        self::assertSame($text, CanonicalEncoder::encode($filters->normalised()));

        $reordered = TrailFilters::none()
            ->withHoldingDataOf(Reference::of('App\Models\User', '42'))
            ->withWindow(new \DateTimeImmutable('2026-11-01T01:00:00+01:00'), null)
            ->withOutcomes([Outcome::FAILURE, Outcome::SUCCESS])
            ->withEventPrefix('invoice.')
            ->withReference('tenant', Reference::of('team', '7'));

        self::assertSame($filters->normalised(), $reordered->normalised());
        self::assertNotSame($filters->normalised(), $filters->withReference('tenant', Reference::of('team', '8'))->normalised());
        self::assertNotSame($filters->normalised(), $filters->withHoldingDataOf(Reference::of('App\Models\User', '43'))->normalised());
    }

    /**
     * The data owner is a dimension apart from the actor and the subject.
     *
     * @return void
     */
    public function testTheOwnerHoldingDataIsADimensionOfItsOwn(): void
    {
        $owner   = Reference::of('App\Models\User', '42');
        $filters = TrailFilters::none()->withReference('subject', $owner)->withHoldingDataOf($owner)->withReference('actor', $owner);

        self::assertSame($owner, $filters->holding);
        self::assertSame([['App\Models\User', '42'], ['App\Models\User', '42'], ['App\Models\User', '42']], [
            $filters->normalised()['actor'],
            $filters->normalised()['subject'],
            $filters->normalised()['holding_data_of'],
        ]);
        self::assertNull(TrailFilters::none()->withReference('subject', $owner)->holding);
        self::assertNull(TrailFilters::none()->withHoldingDataOf($owner)->subject);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reference filter must be on the actor, the subject, the principal or the tenant.');

        TrailFilters::none()->withReference('holding', $owner);
    }

    /**
     * The owner is a sensitive parameter.
     *
     * @return void
     */
    public function testTheOwnerIsSensitive(): void
    {
        $parameter = (new \ReflectionMethod(TrailFilters::class, 'withHoldingDataOf'))->getParameters()[0];

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * No refusal names the value it refused, whichever filter refused it.
     *
     * @return void
     */
    public function testRefusalsNeverNameTheValue(): void
    {
        $refusals = [
            static fn (): TrailFilters => TrailFilters::none()->withReference(self::SECRET, Reference::of('user', '1')),
            static fn (): TrailFilters => TrailFilters::none()->withEvents([self::SECRET]),
            static fn (): TrailFilters => TrailFilters::none()->withEventPrefix(self::SECRET),
            static fn (): TrailFilters => TrailFilters::none()->withCategories([self::SECRET]),
            static fn (): TrailFilters => TrailFilters::none()->withCorrelation(self::SECRET),
        ];

        foreach ($refusals as $index => $refusal) {
            try {
                $refusal();

                self::fail("Expected refusal {$index} to be refused.");
            } catch (\InvalidArgumentException $exception) {
                self::assertStringNotContainsString(self::SECRET, $exception->getMessage(), "Refusal {$index}.");
                self::assertNull($exception->getPrevious(), "Refusal {$index}.");
            }
        }
    }
}
