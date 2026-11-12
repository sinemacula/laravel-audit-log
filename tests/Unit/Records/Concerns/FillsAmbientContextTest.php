<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Concerns;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Concerns\FillsAmbientContext;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\Normalised;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for how contributors fill a pending record's open fields.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRecord::class)]
#[CoversClass(Contribution::class)]
#[CoversTrait(FillsAmbientContext::class)]
final class FillsAmbientContextTest extends TestCase
{
    /** @var string A valid W3C trace id. */
    private const string TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';

    /**
     * Rows of `[fill, the snapshot field, the value expected]`: one row per
     * filler and field.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void, 1: string, 2: array<string, string>|\SineMacula\Laravel\AuditLog\Records\Enums\Origin|\SineMacula\Laravel\AuditLog\Records\Reference|string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideFillers(): iterable
    {
        yield from [
            'the actor' => [static function (PendingRecord $pending): void {
                $pending->fillActor(Reference::of('user', '1'));
            }, 'actor', Reference::of('user', '1')],
            'the principal' => [static function (PendingRecord $pending): void {
                $pending->fillPrincipal(Reference::of('team', '2'));
            }, 'principal', Reference::of('team', '2')],
            'the tenant' => [static function (PendingRecord $pending): void {
                $pending->fillTenant(Reference::of('organisation', '3'));
            }, 'tenant', Reference::of('organisation', '3')],
            'the guard' => [static function (PendingRecord $pending): void {
                $pending->fillGuard('web');
            }, 'guard', 'web'],
            'the session' => [static function (PendingRecord $pending): void {
                $pending->fillSession('sess_ref_1');
            }, 'sessionId', 'sess_ref_1'],
            'the request id' => [static function (PendingRecord $pending): void {
                $pending->fillRequest('req-1');
            }, 'requestId', 'req-1'],
            'the trace id' => [static function (PendingRecord $pending): void {
                $pending->fillRequest(null, self::TRACE);
            }, 'traceId', self::TRACE],
            'the IP address' => [static function (PendingRecord $pending): void {
                $pending->fillClient('203.0.113.7', null);
            }, 'ip', '203.0.113.7'],
            'the user agent' => [static function (PendingRecord $pending): void {
                $pending->fillClient(null, 'Mozilla/5.0');
            }, 'userAgent', 'Mozilla/5.0'],
            'the origin' => [static function (PendingRecord $pending): void {
                $pending->fillOrigin(Origin::QUEUE);
            }, 'origin', Origin::QUEUE],
            'the context' => [static function (PendingRecord $pending): void {
                $pending->fillContext(['job' => 'SendInvoice']);
            }, 'context', ['job' => 'SendInvoice']],
        ];
    }

    /**
     * Each filler sets its field when it is open, and nothing else.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void  $fill
     * @param  string  $field
     * @param  array<string, string>|\SineMacula\Laravel\AuditLog\Records\Enums\Origin|\SineMacula\Laravel\AuditLog\Records\Reference|string  $expected
     * @return void
     */
    #[DataProvider('provideFillers')]
    public function testAFillerSetsAnUnsetField(\Closure $fill, string $field, array|Origin|Reference|string $expected): void
    {
        $pending = new PendingRecord;
        $empty   = self::fields($pending->snapshot());

        $fill($pending);

        $filled = self::fields($pending->snapshot());

        self::assertEquals($expected, $filled[$field]);

        unset($filled[$field], $empty[$field]);

        self::assertEquals($empty, $filled);
    }

    /**
     * A filler never replaces a value given explicitly, an explicit `null`
     * included, for the actor, the principal and the tenant.
     *
     * @return void
     */
    public function testAFillerNeverReplacesAGivenField(): void
    {
        $admin = (new StubUser)->forceFill(['id' => 1]);
        $other = Reference::of('user', '2');

        $given = (new PendingRecord)->by($admin)->asPrincipal(Reference::of('team', '1'))->forTenant(Reference::of('organisation', '1'));
        $none  = (new PendingRecord)->by(null)->asPrincipal(null)->forTenant(null);

        foreach ([$given, $none] as $pending) {
            $pending->fillActor($other);
            $pending->fillPrincipal($other);
            $pending->fillTenant($other);
        }

        self::assertEquals([Reference::of(StubUser::class, '1'), Reference::of('team', '1'), Reference::of('organisation', '1')], self::parties($given->snapshot()));
        self::assertSame([null, null, null], self::parties($none->snapshot()));
    }

    /**
     * An explicit value or `null` given after a filler replaces the filled one,
     * for the actor, the principal and the tenant.
     *
     * @return void
     */
    public function testAnExplicitValueReplacesAFilledOne(): void
    {
        $other   = Reference::of('user', '2');
        $pending = new PendingRecord;

        $pending->fillActor($other);
        $pending->fillPrincipal($other);
        $pending->fillTenant($other);

        $pending->by(Reference::of('user', '1'))->asPrincipal(Reference::of('team', '1'))->forTenant(Reference::of('organisation', '1'));

        self::assertEquals([Reference::of('user', '1'), Reference::of('team', '1'), Reference::of('organisation', '1')], self::parties($pending->snapshot()));

        $pending->by(null)->asPrincipal(null)->forTenant(null);

        self::assertSame([null, null, null], self::parties($pending->snapshot()));
    }

    /**
     * A filler of two fields fills each on its own, never replacing a filled
     * one.
     *
     * @return void
     */
    public function testATwoFieldFillerFillsEachFieldOnItsOwn(): void
    {
        $pending = new PendingRecord;

        $pending->fillRequest('req-1');
        $pending->fillRequest('req-2', self::TRACE);
        $pending->fillClient(null, 'agent');
        $pending->fillClient('203.0.113.7', 'other');

        $snapshot = $pending->snapshot();

        self::assertSame(['req-1', self::TRACE], [$snapshot->requestId, $snapshot->traceId]);
        self::assertSame(['203.0.113.7', 'agent'], [$snapshot->ip, $snapshot->userAgent]);

        $reverse = new PendingRecord;

        $reverse->fillRequest(null, self::TRACE);
        $reverse->fillRequest('req-2', 'ffffffffffffffffffffffffffffffff');
        $reverse->fillClient('203.0.113.7', null);
        $reverse->fillClient('198.51.100.1', 'agent');

        $snapshot = $reverse->snapshot();

        self::assertSame(['req-2', self::TRACE], [$snapshot->requestId, $snapshot->traceId]);
        self::assertSame(['203.0.113.7', 'agent'], [$snapshot->ip, $snapshot->userAgent]);
    }

    /**
     * The first contributor to fill a field wins, for every field.
     *
     * @return void
     */
    public function testTheFirstFillWins(): void
    {
        $pending = new PendingRecord;

        foreach (['1', '2'] as $id) {
            $pending->fillActor(Reference::of('user', $id));
            $pending->fillPrincipal(Reference::of('team', $id));
            $pending->fillTenant(Reference::of('organisation', $id));
            $pending->fillGuard("guard-{$id}");
            $pending->fillSession("sess-{$id}");
            $pending->fillRequest("req-{$id}", str_repeat($id, 32));
            $pending->fillClient("203.0.113.{$id}", "agent-{$id}");
        }

        $snapshot = $pending->snapshot();

        self::assertEquals([Reference::of('user', '1'), Reference::of('team', '1'), Reference::of('organisation', '1')], self::parties($snapshot));
        self::assertSame(['guard-1', 'sess-1', 'req-1', str_repeat('1', 32), '203.0.113.1', 'agent-1'], [
            $snapshot->guard, $snapshot->sessionId, $snapshot->requestId, $snapshot->traceId, $snapshot->ip, $snapshot->userAgent,
        ]);
    }

    /**
     * A filler given `null` changes nothing and leaves the field open for the
     * next contributor, for every field.
     *
     * @return void
     */
    public function testANullFillLeavesTheFieldOpen(): void
    {
        $pending = new PendingRecord;

        $pending->fillActor(null);
        $pending->fillPrincipal(null);
        $pending->fillTenant(null);
        $pending->fillGuard(null);
        $pending->fillSession(null);
        $pending->fillRequest(null, null);
        $pending->fillClient(null, null);

        self::assertEquals((new PendingRecord)->snapshot(), $pending->snapshot());

        $pending->fillActor(Reference::of('user', '1'));
        $pending->fillPrincipal(Reference::of('team', '1'));
        $pending->fillTenant(Reference::of('organisation', '1'));
        $pending->fillGuard('web');
        $pending->fillSession('sess-1');
        $pending->fillRequest('req-1', self::TRACE);
        $pending->fillClient('203.0.113.7', 'agent');

        $snapshot = $pending->snapshot();

        self::assertEquals([Reference::of('user', '1'), Reference::of('team', '1'), Reference::of('organisation', '1')], self::parties($snapshot));
        self::assertSame(['web', 'sess-1', 'req-1', self::TRACE, '203.0.113.7', 'agent'], [
            $snapshot->guard, $snapshot->sessionId, $snapshot->requestId, $snapshot->traceId, $snapshot->ip, $snapshot->userAgent,
        ]);
    }

    /**
     * Context adds only the top-level keys it does not hold yet, so the first
     * contributor to name a key wins, and later calls still add new keys.
     *
     * @return void
     */
    public function testFillContextAddsOnlyMissingKeys(): void
    {
        $pending = new PendingRecord;

        $pending->fillContext(['route' => 'invoices.approve', 'meta' => ['a' => 1]]);
        $pending->fillContext(['route' => 'other', 'method' => 'POST', 'meta' => ['b' => 2]]);
        $pending->fillContext([]);

        self::assertSame(['route' => 'invoices.approve', 'meta' => ['a' => 1], 'method' => 'POST'], $pending->snapshot()->context);
    }

    /**
     * Context is normalised like properties: models become references, enums
     * their values and strings are cleaned.
     *
     * @return void
     */
    public function testFillContextNormalisesTheContext(): void
    {
        $pending = new PendingRecord;

        $pending->fillContext(['user' => (new StubUser)->forceFill(['id' => 6]), 'colour' => StubColour::RED, "com\0mand" => "a\nb"]);

        self::assertSame(['user' => ['type' => StubUser::class, 'id' => '6'], 'colour' => 'red', 'command' => 'a b'], $pending->snapshot()->context);
    }

    /**
     * A list is not a map of names to values, and is refused.
     *
     * @return void
     */
    public function testFillContextRefusesAList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Context is a map of names to values, not a list.');

        (new PendingRecord)->fillContext(['invoices.approve']);
    }

    /**
     * Only the properties reserve keys beginning `_audit`: the context keeps
     * them, at the top level and nested, as given.
     *
     * @return void
     */
    public function testFillContextKeepsKeysBeginningTheReservedPrefix(): void
    {
        $pending = new PendingRecord;

        $pending->fillContext(['_audit' => ['note' => 'x'], 'meta' => ['_auditor' => 'y']]);

        self::assertSame(['_audit' => ['note' => 'x'], 'meta' => ['_auditor' => 'y']], $pending->snapshot()->context);
    }

    /**
     * Context keys that collide once cleaned keep the first value and are
     * diagnosed by their segments, accumulated across calls.
     *
     * @return void
     */
    public function testContextCollisionsAreCarriedBySegment(): void
    {
        $pending = new PendingRecord;

        $pending->fillContext(['a' => 1, "a\0" => 2]);
        $pending->fillContext(['b.c' => [['x' => 1, "x\0" => 2]]]);

        $snapshot = $pending->snapshot();

        self::assertSame(['a' => 1, 'b.c' => [['x' => 1]]], $snapshot->context);
        self::assertSame([['a'], ['b.c', 0, 'x']], $snapshot->contextCollisions);
        self::assertSame(2, $snapshot->contextCollisionCount);
    }

    /**
     * At most 32 context collision paths are kept across every call, the first
     * met, while the count covers every one.
     *
     * @return void
     */
    public function testContextCollisionsAreCappedWhileTheCountContinues(): void
    {
        $pending = new PendingRecord;

        foreach (range(0, 39) as $index) {
            $pending->fillContext(["k{$index}" => 1, "k{$index}\0" => 2]);
        }

        $snapshot = $pending->snapshot();

        self::assertCount(Normalised::MAX_COLLISIONS, $snapshot->contextCollisions);
        self::assertSame(['k0'], $snapshot->contextCollisions[0]);
        self::assertSame(['k31'], $snapshot->contextCollisions[31]);
        self::assertSame(40, $snapshot->contextCollisionCount);
    }

    /**
     * A list is refused before anything is carried: not the context, nor the
     * collisions met inside it, and what was filled before is unchanged.
     *
     * @return void
     */
    public function testARefusedContextCarriesNoCollision(): void
    {
        $pending = new PendingRecord;

        $pending->fillContext(['a' => 1, "a\0" => 2]);

        try {
            $pending->fillContext([['x' => 1, "x\0" => 2]]);
            self::fail('Expected the list to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Context is a map of names to values, not a list.', $exception->getMessage());
        }

        $snapshot = $pending->snapshot();

        self::assertSame(['a' => 1], $snapshot->context);
        self::assertSame([['a']], $snapshot->contextCollisions);
        self::assertSame(1, $snapshot->contextCollisionCount);
    }

    /**
     * A builder holds no context collision until a context with one is filled.
     *
     * @return void
     */
    public function testAFreshBuilderHasNoContextCollisions(): void
    {
        $fresh  = new PendingRecord;
        $filled = new PendingRecord;

        $filled->fillContext(['route' => 'invoices.approve']);

        self::assertSame([], $fresh->snapshot()->contextCollisions);
        self::assertSame(0, $fresh->snapshot()->contextCollisionCount);
        self::assertSame([], $filled->snapshot()->contextCollisions);
        self::assertSame(0, $filled->snapshot()->contextCollisionCount);
    }

    /**
     * Context collisions and property collisions are carried apart, so neither
     * is mistaken for the other.
     *
     * @return void
     */
    public function testContextAndPropertyCollisionsAreKeptApart(): void
    {
        $pending = (new PendingRecord)->withProperties(['p' => 1, "p\0" => 2]);

        $pending->fillContext(['c' => 1, "c\0" => 2]);

        $snapshot = $pending->snapshot();

        self::assertSame([['p']], $snapshot->collisions);
        self::assertSame(1, $snapshot->collisionCount);
        self::assertSame([['c']], $snapshot->contextCollisions);
        self::assertSame(1, $snapshot->contextCollisionCount);
    }

    /**
     * A contributor's context reaches the builder's diagnostics through its
     * view of the builder, as any filler's value does.
     *
     * @return void
     */
    public function testAContributorsContextCollisionsAreCarried(): void
    {
        $pending = new PendingRecord;

        (new Contribution($pending))->fillContext(['a' => 1, "a\0" => 2]);

        self::assertSame([['a']], $pending->snapshot()->contextCollisions);
        self::assertSame(1, $pending->snapshot()->contextCollisionCount);
    }

    /**
     * The context parameter is marked sensitive wherever a refusal can be
     * thrown with it on the stack.
     *
     * @return void
     */
    public function testTheContextIsMarkedSensitive(): void
    {
        $builder = (new \ReflectionMethod(PendingRecord::class, 'fillContext'))->getParameters()[0];
        $view    = (new \ReflectionMethod(Contribution::class, 'fillContext'))->getParameters()[0];
        $mapOf   = (new \ReflectionMethod(PendingRecord::class, 'mapOf'))->getParameters()[0];

        self::assertCount(1, $builder->getAttributes(\SensitiveParameter::class));
        self::assertCount(1, $view->getAttributes(\SensitiveParameter::class));
        self::assertCount(1, $mapOf->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A refused context leaves no value in the exception's stack trace, even
     * with every frame keeping its arguments.
     *
     * @return void
     */
    public function testARefusedContextStaysOutOfTheStackTrace(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            (new Contribution(new PendingRecord))->fillContext(['planted-value']);
            self::fail('Expected the list to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString('planted', print_r($exception->getTrace(), true));
            self::assertStringNotContainsString('planted', (string) $exception);
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * The user agent is cleaned of controls and cut at 512 bytes; one that is
     * empty once cleaned counts as none, so the next contributor can fill it.
     *
     * @return void
     */
    public function testFillClientSanitisesAndCapsTheUserAgent(): void
    {
        $cleaned = new PendingRecord;
        $capped  = new PendingRecord;
        $empty   = new PendingRecord;

        $cleaned->fillClient(null, "Mozilla\0/5.0\t(X11)\u{202E}");
        $capped->fillClient(null, str_repeat('é', 300));
        $empty->fillClient(null, "\0\u{202E}");

        self::assertSame('Mozilla/5.0 (X11)', $cleaned->snapshot()->userAgent);
        self::assertSame(str_repeat('é', 256), $capped->snapshot()->userAgent);
        self::assertNull($empty->snapshot()->userAgent);

        $empty->fillClient(null, 'Mozilla/5.0');

        self::assertSame('Mozilla/5.0', $empty->snapshot()->userAgent);
    }

    /**
     * Rows of `[trace id]`: valid W3C trace ids.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTraceIds(): iterable
    {
        yield from [
            'the W3C example' => [self::TRACE],
            'all f'           => [str_repeat('f', 32)],
            'one non-zero'    => [str_repeat('0', 31) . '1'],
        ];
    }

    /**
     * Each valid trace id is kept exactly.
     *
     * @param  string  $traceId
     * @return void
     */
    #[DataProvider('provideTraceIds')]
    public function testFillRequestKeepsAValidTraceId(string $traceId): void
    {
        $pending = new PendingRecord;
        $pending->fillRequest(null, $traceId);

        self::assertSame($traceId, $pending->snapshot()->traceId);
    }

    /**
     * Rows of `[trace id]`: ids that are too short, too long, upper case, all
     * zero or not hexadecimal.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedTraceIds(): iterable
    {
        yield from [
            '31 digits'           => [substr(self::TRACE, 0, 31)],
            '33 digits'           => [self::TRACE . 'a'],
            'upper case'          => [strtoupper(self::TRACE)],
            '32 zeros'            => [str_repeat('0', 32)],
            'not hexadecimal'     => [str_repeat('g', 32)],
            'a trailing new line' => [self::TRACE . "\n"],
        ];
    }

    /**
     * Each malformed trace id is refused, and the request id given with it is
     * not filled either.
     *
     * @param  string  $traceId
     * @return void
     */
    #[DataProvider('provideRefusedTraceIds')]
    public function testFillRequestRefusesAMalformedTraceId(string $traceId): void
    {
        $pending = new PendingRecord;

        try {
            $pending->fillRequest('req-1', $traceId);
            self::fail('Expected the trace id to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A trace id must be 32 lower-case hexadecimal digits, not all zero.', $exception->getMessage());
        }

        self::assertNull($pending->snapshot()->requestId);
    }

    /**
     * Rows of `[fill, message]`: values outside their columns or not clean.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void, 1: string}>
     */
    public static function provideRefusedAmbientValues(): iterable
    {
        $guard   = 'A guard name must be from 1 to 64 characters, with no control characters.';
        $session = 'A session reference must be from 1 to 191 characters, with no control characters.';
        $request = 'A request id must be from 1 to 64 characters, with no control characters.';

        yield from [
            'a 65-character guard' => [static function (PendingRecord $pending): void {
                $pending->fillGuard(str_repeat('g', 65));
            }, $guard],
            'an empty guard' => [static function (PendingRecord $pending): void {
                $pending->fillGuard('');
            }, $guard],
            'a guard with a new line' => [static function (PendingRecord $pending): void {
                $pending->fillGuard("web\n");
            }, $guard],
            'a 192-character session reference' => [static function (PendingRecord $pending): void {
                $pending->fillSession(str_repeat('s', 192));
            }, $session],
            'a 65-character request id' => [static function (PendingRecord $pending): void {
                $pending->fillRequest(str_repeat('r', 65));
            }, $request],
        ];
    }

    /**
     * Each value outside its column, or not clean, is refused with its column's
     * limit, even when the field is already filled.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): void  $fill
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedAmbientValues')]
    public function testFillersRefuseValuesOutsideTheirColumns(\Closure $fill, string $message): void
    {
        foreach ([new PendingRecord, self::filled()] as $pending) {
            try {
                $fill($pending);
                self::fail('Expected the value to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * Values exactly as long as their columns, counted in characters, are kept.
     *
     * @return void
     */
    public function testFillersKeepValuesAsLongAsTheirColumns(): void
    {
        $pending = new PendingRecord;

        $pending->fillGuard(str_repeat('é', 64));
        $pending->fillSession(str_repeat('é', 191));
        $pending->fillRequest(str_repeat('é', 64));

        $snapshot = $pending->snapshot();

        self::assertSame([str_repeat('é', 64), str_repeat('é', 191), str_repeat('é', 64)], [
            $snapshot->guard, $snapshot->sessionId, $snapshot->requestId,
        ]);
    }

    /**
     * Rows of `[address]`: strings no address could be, each of which an
     * identifier's check would have refused.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideGarbageAddresses(): iterable
    {
        yield from [
            'empty'           => [''],
            'over-long'       => [str_repeat('1', 256)],
            'a NUL'           => ["203.0.113.7\0"],
            'not valid UTF-8' => ["203.0.113.7\xFF"],
        ];
    }

    /**
     * No address is refused, so a bad one cannot lose the record; minimising
     * stores it as `null`.
     *
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideGarbageAddresses')]
    public function testFillClientRefusesNoAddress(string $address): void
    {
        $pending = new PendingRecord;

        $pending->fillClient($address, null);
        $pending->fillClient('203.0.113.7', null);

        self::assertSame($address, $pending->snapshot()->ip);
    }

    /**
     * The origin is filled.
     *
     * @return void
     */
    public function testFillOriginSetsTheOrigin(): void
    {
        $pending = new PendingRecord;
        $pending->fillOrigin(Origin::CONSOLE);

        self::assertSame(Origin::CONSOLE, $pending->snapshot()->origin);
    }

    /**
     * The first origin filled wins.
     *
     * @return void
     */
    public function testTheFirstOriginWins(): void
    {
        $pending = new PendingRecord;
        $pending->fillOrigin(Origin::HTTP);
        $pending->fillOrigin(Origin::QUEUE);

        self::assertSame(Origin::HTTP, $pending->snapshot()->origin);
    }

    /**
     * A builder nobody has touched has no settled actor.
     *
     * @return void
     */
    public function testNoActorIsSettledAtFirst(): void
    {
        self::assertFalse((new PendingRecord)->isActorSettled());
    }

    /**
     * `by(null)` says there is explicitly no actor, which settles it.
     *
     * @return void
     */
    public function testByNullSettlesTheActor(): void
    {
        self::assertTrue((new PendingRecord)->by(null)->isActorSettled());
    }

    /**
     * A contributor's actor settles it, so no later contributor replaces it.
     *
     * @return void
     */
    public function testAFilledActorSettlesIt(): void
    {
        $pending = new PendingRecord;

        $pending->fillActor(Reference::of('user', '1'));

        self::assertTrue($pending->isActorSettled());
    }

    /**
     * A contributor with no actor to give leaves it open for the next.
     *
     * @return void
     */
    public function testAFillerGivenNullLeavesTheActorUnsettled(): void
    {
        $pending = new PendingRecord;

        $pending->fillActor(null);

        self::assertFalse($pending->isActorSettled());
    }

    /**
     * Another field being filled does not settle the actor.
     *
     * @return void
     */
    public function testAnotherFieldDoesNotSettleTheActor(): void
    {
        $pending = new PendingRecord;

        $pending->fillGuard('web');
        $pending->fillPrincipal(Reference::of('team', '2'));

        self::assertFalse($pending->isActorSettled());
    }

    /**
     * A used builder refuses every filler, so nothing changes what was
     * recorded.
     *
     * @return void
     */
    public function testAUsedBuilderRefusesEveryFiller(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        $pending->consume();

        foreach (self::provideFillers() as $name => [$fill]) {
            try {
                $fill($pending);

                self::fail(sprintf('Expected the used builder to refuse %s.', $name));
            } catch (\LogicException $exception) {
                self::assertSame('A pending record is recorded once, and this one has already been recorded.', $exception->getMessage(), $name);
            }
        }
    }

    /**
     * A used builder refuses the question, as it refuses every other call.
     *
     * @return void
     */
    public function testAUsedBuilderRefusesTheQuestion(): void
    {
        $pending = (new PendingRecord)->event('invoice.approved');

        $pending->consume();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record is recorded once, and this one has already been recorded.');

        $pending->isActorSettled();
    }

    /**
     * A builder with every ambient field filled.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function filled(): PendingRecord
    {
        $pending = new PendingRecord;

        $pending->fillGuard('web');
        $pending->fillSession('sess-1');
        $pending->fillRequest('req-1', self::TRACE);
        $pending->fillClient('203.0.113.7', 'agent');

        return $pending;
    }

    /**
     * The snapshot's actor, principal and tenant.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return list<?\SineMacula\Laravel\AuditLog\Records\Reference>
     */
    private static function parties(PendingSnapshot $snapshot): array
    {
        return [$snapshot->actor, $snapshot->principal, $snapshot->tenant];
    }

    /**
     * The snapshot's fields, by name.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return array<string, array<array-key, array<array-key, scalar>|scalar|null>|object|scalar|null>
     */
    private static function fields(PendingSnapshot $snapshot): array
    {
        /** @var array<string, array<array-key, array<array-key, scalar>|scalar|null>|object|scalar|null> */
        return get_object_vars($snapshot);
    }
}
