<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for the view of a pending record a contributor gets: each filler
 * reaches the builder, the builder's rules stay in force through it, what it
 * reads, and that it offers no way to record the record or choose its timing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Contribution::class)]
final class ContributionTest extends TestCase
{
    /** @var string A valid W3C trace id. */
    private const string TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';

    /**
     * Rows of `[fill, the envelope's fields expected]`: one row per filler and
     * field.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\Contribution): void, 1: array<string, array<string, string>|string>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideFillers(): iterable
    {
        yield from [
            'the actor' => [static function (Contribution $contribution): void {
                $contribution->fillActor(Reference::of('user', '1'));
            }, ['actor_type' => 'user', 'actor_id' => '1']],
            'the principal' => [static function (Contribution $contribution): void {
                $contribution->fillPrincipal(Reference::of('team', '2'));
            }, ['principal_type' => 'team', 'principal_id' => '2']],
            'the tenant' => [static function (Contribution $contribution): void {
                $contribution->fillTenant(Reference::of('organisation', '3'));
            }, ['tenant_type' => 'organisation', 'tenant_id' => '3']],
            'the guard' => [static function (Contribution $contribution): void {
                $contribution->fillGuard('web');
            }, ['guard' => 'web']],
            'the session' => [static function (Contribution $contribution): void {
                $contribution->fillSession('sess_ref_1');
            }, ['session_id' => 'sess_ref_1']],
            'the request id' => [static function (Contribution $contribution): void {
                $contribution->fillRequest('req-1');
            }, ['request_id' => 'req-1']],
            'the request and trace ids' => [static function (Contribution $contribution): void {
                $contribution->fillRequest('req-1', self::TRACE);
            }, ['request_id' => 'req-1', 'trace_id' => self::TRACE]],
            'the client' => [static function (Contribution $contribution): void {
                $contribution->fillClient('203.0.113.7', 'Mozilla/5.0');
            }, ['ip' => '203.0.113.7', 'user_agent' => 'Mozilla/5.0']],
            'the origin' => [static function (Contribution $contribution): void {
                $contribution->fillOrigin(Origin::QUEUE);
            }, ['origin' => 'queue']],
            'the context' => [static function (Contribution $contribution): void {
                $contribution->fillContext(['job' => 'SendInvoice']);
            }, ['context' => ['job' => 'SendInvoice']]],
        ];
    }

    /**
     * Each filler reaches the captured record.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\Contribution): void  $fill
     * @param  array<string, array<string, string>|string>  $expected
     * @return void
     */
    #[DataProvider('provideFillers')]
    public function testEachFillerFillsTheRecord(\Closure $fill, array $expected): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        $fill(new Contribution($pending));

        // Every record needs an origin; this stands only if the row gave none
        $pending->fillOrigin(Origin::HTTP);

        $envelope = $this->captured($pending);

        foreach ($expected as $field => $value) {
            self::assertSame($value, $envelope[$field], $field);
        }
    }

    /**
     * A value the caller gave explicitly is never replaced, `by(null)`
     * included.
     *
     * @return void
     */
    public function testAnExplicitValueIsNeverReplaced(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved')->by(null)->forTenant(Reference::of('organisation', '9'));

        $pending->fillOrigin(Origin::HTTP);

        $contribution = new Contribution($pending);

        $contribution->fillActor(Reference::of('user', '1'));
        $contribution->fillTenant(Reference::of('organisation', '3'));

        $envelope = $this->captured($pending);

        self::assertNull($envelope['actor_type']);
        self::assertNull($envelope['actor_id']);
        self::assertSame('9', $envelope['tenant_id']);
    }

    /**
     * The first contributor to fill a field wins.
     *
     * @return void
     */
    public function testTheFirstContributorToFillWins(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        $pending->fillOrigin(Origin::HTTP);

        (new Contribution($pending))->fillGuard('web');
        (new Contribution($pending))->fillGuard('api');

        self::assertSame('web', $this->captured($pending)['guard']);
    }

    /**
     * A malformed value is refused by the builder, with the builder's message.
     *
     * @return void
     */
    public function testAMalformedValueIsRefusedByTheBuilder(): void
    {
        $contribution = new Contribution(new PendingRecord);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A guard name must be from 1 to 64 characters, with no control characters.');

        $contribution->fillGuard('');
    }

    /**
     * The view reads the code and the subject as they stand.
     *
     * @return void
     */
    public function testReadsTheCodeAndSubject(): void
    {
        $subject = Reference::of('invoice', 'inv_0042');
        $pending = (new PendingRecord)->event('invoice.approved');

        $contribution = new Contribution($pending);

        self::assertSame('invoice.approved', $contribution->code());
        self::assertNull($contribution->subject());

        $pending->on($subject);

        self::assertEquals($subject, $contribution->subject());
    }

    /**
     * Asking for the code of a builder with none is a programming error, with
     * the builder's message.
     *
     * @return void
     */
    public function testACodelessBuilderIsALogicError(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record needs an event code before it is recorded; set one with `event()`.');

        (new Contribution(new PendingRecord))->code();
    }

    /**
     * The view reads the actor given or filled so far.
     *
     * @return void
     */
    public function testReadsTheActor(): void
    {
        $actor        = Reference::of('user', '1');
        $contribution = new Contribution(new PendingRecord);

        self::assertNull($contribution->actor());

        $contribution->fillActor($actor);

        self::assertSame($actor, $contribution->actor());
    }

    /**
     * Neither no actor nor `by(null)` is a present actor, and a given or a
     * filled one is.
     *
     * @return void
     */
    public function testHasActorIsFalseForNoActorAndForByNull(): void
    {
        $filled = new Contribution(new PendingRecord);

        self::assertFalse($filled->hasActor());
        self::assertFalse((new Contribution((new PendingRecord)->by(null)))->hasActor());
        self::assertTrue((new Contribution((new PendingRecord)->by(Reference::of('user', '1'))))->hasActor());

        $filled->fillActor(Reference::of('user', '1'));

        self::assertTrue($filled->hasActor());
    }

    /**
     * `by(null)` settles the actor and no actor yet does not, which is what a
     * contributor needs to tell them apart.
     *
     * @return void
     */
    public function testIsActorSettledTellsByNullFromNoActor(): void
    {
        self::assertFalse((new Contribution(new PendingRecord))->isActorSettled());
        self::assertTrue((new Contribution((new PendingRecord)->by(null)))->isActorSettled());
    }

    /**
     * The whole public surface, compared in order, offers nothing of timing,
     * properties, the note or `record()`.
     *
     * @return void
     */
    public function testExposesNoWayToRecordOrChooseTiming(): void
    {
        $methods = array_map(
            static fn (\ReflectionMethod $method): string => $method->getName(),
            (new \ReflectionClass(Contribution::class))->getMethods(\ReflectionMethod::IS_PUBLIC),
        );

        self::assertSame([
            '__construct',
            'fillActor',
            'fillPrincipal',
            'fillTenant',
            'fillGuard',
            'fillSession',
            'fillRequest',
            'fillClient',
            'fillOrigin',
            'fillContext',
            'code',
            'subject',
            'actor',
            'hasActor',
            'isActorSettled',
        ], $methods);
    }

    /**
     * Once the record is built, the view is refused as the builder is, so a
     * contributor that kept one cannot change or read what was recorded.
     *
     * @return void
     */
    public function testAConsumedBuilderRefusesTheView(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        $pending->fillOrigin(Origin::HTTP);

        $contribution = new Contribution($pending);

        $this->captured($pending);

        $reads = [
            static fn (): string => $contribution->code(),
            static fn (): ?Reference => $contribution->subject(),
            static fn (): bool => $contribution->isActorSettled(),
        ];

        foreach ($reads as $read) {
            try {
                $read();

                self::fail('Expected the used builder to refuse.');
            } catch (\LogicException $exception) {
                self::assertSame('A pending record is recorded once, and this one has already been recorded.', $exception->getMessage());
            }
        }
    }

    /**
     * The envelope of the record the builder captures.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return array<string, mixed>
     */
    private function captured(PendingRecord $pending): array
    {
        $occurredAt = new \DateTimeImmutable('2026-11-01 12:00:00', new \DateTimeZone('UTC'));

        return AuditRecord::fromPending($pending, RecordFactory::minimisedOf($pending), 1, 'finance', $occurredAt, 'app')->toArray();
    }
}
