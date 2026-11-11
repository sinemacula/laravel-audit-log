<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use Illuminate\Events\Dispatcher;
use Illuminate\Log\Context\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;

/**
 * Unit tests for what the package keeps in hidden Context: the keys, the actor
 * going out as three strings and coming back, every malformed envelope being no
 * actor rather than an error, and the rest of Context being left alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CarriedContext::class)]
final class CarriedContextTest extends TestCase
{
    /** @var array<string, string> A well-formed envelope. */
    private const array ENVELOPE = [
        CarriedContext::ACTOR_TYPE  => 'App\Models\User',
        CarriedContext::ACTOR_ID    => '42',
        CarriedContext::ACTOR_GUARD => 'web',
    ];

    /**
     * `CarriedContext` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(CarriedContext::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(CarriedContext::class, $instance);
    }

    /**
     * The hidden keys are the documented ones, since a queued job carries them
     * across a deployment.
     *
     * @return void
     */
    public function testTheKeysAreTheOnesDocumented(): void
    {
        self::assertSame('audit-log.request_id', CarriedContext::REQUEST_ID);
        self::assertSame('audit-log.trace_id', CarriedContext::TRACE_ID);
        self::assertSame('audit-log.actor_type', CarriedContext::ACTOR_TYPE);
        self::assertSame('audit-log.actor_id', CarriedContext::ACTOR_ID);
        self::assertSame('audit-log.actor_guard', CarriedContext::ACTOR_GUARD);
        self::assertSame('audit-log.principal_type', CarriedContext::PRINCIPAL_TYPE);
        self::assertSame('audit-log.principal_id', CarriedContext::PRINCIPAL_ID);
        self::assertSame('audit-log.tenant_type', CarriedContext::TENANT_TYPE);
        self::assertSame('audit-log.tenant_id', CarriedContext::TENANT_ID);
        self::assertSame('audit-log.session', CarriedContext::SESSION);
    }

    /**
     * Carrying an actor adds three hidden strings, and nothing visible.
     *
     * @return void
     */
    public function testCarriesScalarsOnly(): void
    {
        $context = self::context();

        CarriedContext::carryActor($context, new ActorSnapshot(new HeldActor(Reference::of('App\Models\User', 42)), 'web'));

        self::assertSame(self::ENVELOPE, $context->allHidden());
        self::assertSame([], $context->all());
    }

    /**
     * A carried actor reads back as it went out.
     *
     * @return void
     */
    public function testReadsACarriedActorBack(): void
    {
        $context = self::context();

        CarriedContext::carryActor($context, new ActorSnapshot(new HeldActor(Reference::of('App\Models\User', '42')), 'web'));

        $actor = CarriedContext::actor($context);

        self::assertNotNull($actor);
        self::assertSame('App\Models\User', $actor->held->actor->type);
        self::assertSame('42', $actor->held->actor->id);
        self::assertSame('web', $actor->guard);
    }

    /**
     * The actor's principal, tenant and session read back as they went out.
     *
     * @return void
     */
    public function testReadsTheCarriedContextBack(): void
    {
        $context = self::context();

        CarriedContext::carryActor($context, self::fullSnapshot());

        self::assertEquals(self::fullSnapshot(), CarriedContext::actor($context));
    }

    /**
     * Carrying an actor replaces the whole envelope, so the context of an
     * earlier actor never goes on with a later one.
     *
     * @return void
     */
    public function testCarryingReplacesTheWholeEnvelope(): void
    {
        $context = self::context();

        CarriedContext::carryActor($context, self::fullSnapshot());
        CarriedContext::carryActor($context, new ActorSnapshot(new HeldActor(Reference::of('App\Models\User', 42)), 'web'));

        self::assertSame(self::ENVELOPE, $context->allHidden());
    }

    /**
     * An envelope naming a class that no longer exists still reads back: the
     * snapshot is never resolved, so nothing looks for it.
     *
     * @return void
     */
    public function testAnEnvelopeIsNeverResolved(): void
    {
        $context = self::context()->addHidden([...self::ENVELOPE, CarriedContext::ACTOR_TYPE => 'App\Models\Gone']);

        self::assertSame('App\Models\Gone', CarriedContext::actor($context)?->held->actor->type);
    }

    /**
     * Context with no envelope carries no actor.
     *
     * @return void
     */
    public function testNoEnvelopeIsNoActor(): void
    {
        self::assertNull(CarriedContext::actor(self::context()));
    }

    /**
     * The envelope is read from the hidden values alone: a visible value under
     * the same keys, which an application's own code might add, is no actor.
     *
     * @return void
     */
    public function testAVisibleValueIsNoActor(): void
    {
        self::assertNull(CarriedContext::actor(self::context()->add(self::ENVELOPE)));
    }

    /**
     * Rows of `[envelope]`: each part replaced by what a payload might hold, or
     * missing.
     *
     * @return iterable<string, array{0: array<string, array<int, string>|bool|int|string|null>}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        yield from [
            'an array for the type'       => [[...self::ENVELOPE, CarriedContext::ACTOR_TYPE => ['App\Models\User']]],
            'an array for the id'         => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => ['42']]],
            'an array for the guard'      => [[...self::ENVELOPE, CarriedContext::ACTOR_GUARD => ['web']]],
            'an integer for the type'     => [[...self::ENVELOPE, CarriedContext::ACTOR_TYPE => 42]],
            'an integer for the id'       => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => 42]],
            'an integer for the guard'    => [[...self::ENVELOPE, CarriedContext::ACTOR_GUARD => 42]],
            'a boolean for the id'        => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => true]],
            'null for the id'             => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => null]],
            'an empty type'               => [[...self::ENVELOPE, CarriedContext::ACTOR_TYPE => '']],
            'an empty id'                 => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => '']],
            'an empty guard'              => [[...self::ENVELOPE, CarriedContext::ACTOR_GUARD => '']],
            'a missing type'              => [array_diff_key(self::ENVELOPE, [CarriedContext::ACTOR_TYPE => true])],
            'a missing id'                => [array_diff_key(self::ENVELOPE, [CarriedContext::ACTOR_ID => true])],
            'a missing guard'             => [array_diff_key(self::ENVELOPE, [CarriedContext::ACTOR_GUARD => true])],
            'a 192-character type'        => [[...self::ENVELOPE, CarriedContext::ACTOR_TYPE => str_repeat('a', 192)]],
            'a 192-character id'          => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => str_repeat('a', 192)]],
            'a 65-character guard'        => [[...self::ENVELOPE, CarriedContext::ACTOR_GUARD => str_repeat('a', 65)]],
            'a control character type'    => [[...self::ENVELOPE, CarriedContext::ACTOR_TYPE => "App\0User"]],
            'a control character id'      => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => "4\n2"]],
            'a control character guard'   => [[...self::ENVELOPE, CarriedContext::ACTOR_GUARD => "we\tb"]],
            'invalid UTF-8 in the id'     => [[...self::ENVELOPE, CarriedContext::ACTOR_ID => "4\xC32"]],
            'a principal with no id'      => [[...self::ENVELOPE, CarriedContext::PRINCIPAL_TYPE => 'principal']],
            'a tenant with no type'       => [[...self::ENVELOPE, CarriedContext::TENANT_ID => 't-1']],
            'an integer principal id'     => [[...self::ENVELOPE, CarriedContext::PRINCIPAL_TYPE => 'principal', CarriedContext::PRINCIPAL_ID => 7]],
            'an empty tenant id'          => [[...self::ENVELOPE, CarriedContext::TENANT_TYPE => 'tenant', CarriedContext::TENANT_ID => '']],
            'an array for the session'    => [[...self::ENVELOPE, CarriedContext::SESSION => ['session-1']]],
            'an empty session'            => [[...self::ENVELOPE, CarriedContext::SESSION => '']],
            'a control character session' => [[...self::ENVELOPE, CarriedContext::SESSION => "sess\nion"]],
        ];
    }

    /**
     * Each malformed envelope is no actor, and is never an exception, whichever
     * part of it is wrong.
     *
     * @param  array<string, array<int, string>|bool|int|string|null>  $envelope
     * @return void
     */
    #[DataProvider('provideMalformedEnvelopes')]
    public function testEachMalformedEnvelopeIsIgnored(array $envelope): void
    {
        self::assertNull(CarriedContext::actor(self::context()->addHidden($envelope)));
    }

    /**
     * Forgetting the actor removes its three keys, so the request id and trace
     * id stay.
     *
     * @return void
     */
    public function testForgettingRemovesOnlyTheActorKeys(): void
    {
        $context = self::context()->addHidden([
            ...self::ENVELOPE,
            CarriedContext::PRINCIPAL_TYPE => 'principal',
            CarriedContext::PRINCIPAL_ID   => 'p-1',
            CarriedContext::TENANT_TYPE    => 'tenant',
            CarriedContext::TENANT_ID      => 't-1',
            CarriedContext::SESSION        => 'session-1',
            CarriedContext::REQUEST_ID     => 'app:request-1',
            CarriedContext::TRACE_ID       => '4bf92f3577b34da6a3ce929d0e0e4736',
        ]);

        CarriedContext::forgetActor($context);

        self::assertNull(CarriedContext::actor($context));
        self::assertSame([
            CarriedContext::REQUEST_ID => 'app:request-1',
            CarriedContext::TRACE_ID   => '4bf92f3577b34da6a3ce929d0e0e4736',
        ], $context->allHidden());
    }

    /**
     * Carrying and forgetting an actor touch nothing of the application's,
     * visible or hidden, a visible value under one of the same keys included.
     *
     * @return void
     */
    public function testTheRestOfContextIsLeftAlone(): void
    {
        $context = self::context()
            ->add(['tenant' => 'acme', CarriedContext::ACTOR_ID => 'visible'])
            ->addHidden('app.secret', 'kept');

        CarriedContext::carryActor($context, new ActorSnapshot(new HeldActor(Reference::of('App\Models\User', '42')), 'web'));
        CarriedContext::actor($context);

        self::assertSame(['tenant' => 'acme', CarriedContext::ACTOR_ID => 'visible'], $context->all());
        self::assertSame('kept', $context->getHidden('app.secret'));

        CarriedContext::forgetActor($context);

        self::assertSame(['tenant' => 'acme', CarriedContext::ACTOR_ID => 'visible'], $context->all());
        self::assertSame(['app.secret' => 'kept'], $context->allHidden());
    }

    /**
     * A snapshot with a principal, a tenant and a session.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot
     */
    private static function fullSnapshot(): ActorSnapshot
    {
        return new ActorSnapshot(new HeldActor(Reference::of('App\Models\User', '42'), Reference::of('principal', 'p-1'), Reference::of('tenant', 't-1'), 'session-1'), 'web');
    }

    /**
     * A new, empty Context.
     *
     * @return \Illuminate\Log\Context\Repository
     */
    private static function context(): Repository
    {
        return new Repository(new Dispatcher);
    }
}
