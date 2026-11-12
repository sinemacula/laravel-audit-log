<?php

declare(strict_types = 1);

namespace Tests\Feature\Contributors;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Log\Context\Repository;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubForeignGuard;
use Tests\Unit\Stubs\StubHeldActorReader;

/**
 * Feature tests for the default actor contributor: explicit, ambient and
 * carried actors and which one wins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActorContributor::class)]
final class ActorContributorTest extends TestCase
{
    /**
     * The ambient actor and the guard that gave it are filled.
     *
     * @return void
     */
    public function testFillsTheAmbientActorAndGuard(): void
    {
        Auth::guard('web')->setUser(self::user());

        $snapshot = $this->contributed();

        self::assertTrue(Reference::of(StubAuthUser::class, 42)->equals(self::actorOf($snapshot)));
        self::assertSame('web', $snapshot->guard);
    }

    /**
     * An explicit actor is kept and the guard stays empty: the column means the
     * guard that gave this actor.
     *
     * @return void
     */
    public function testAnExplicitActorIsKeptAndFillsNoGuard(): void
    {
        Auth::guard('web')->setUser(self::user());

        $explicit = Reference::of('admin', 'admin-1');
        $pending  = (new PendingRecord)->event('invoice.approved')->by($explicit);

        $snapshot = $this->contributed($pending);

        self::assertSame($explicit, $snapshot->actor);
        self::assertNull($snapshot->guard);
    }

    /**
     * `by(null)` stays no actor, with a user signed in, and fills no guard.
     *
     * @return void
     */
    public function testAnExplicitNullStaysNullAndFillsNoGuard(): void
    {
        Auth::guard('web')->setUser(self::user());

        $snapshot = $this->contributed((new PendingRecord)->event('invoice.approved')->by(null));

        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->guard);
    }

    /**
     * An explicit actor is kept when the guards cannot be read, while an open
     * one still fails on that misconfiguration.
     *
     * @return void
     */
    public function testUnreadableGuardsNeverFailAnExplicitActor(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', ['not-configured']);

        $explicit = Reference::of('admin', 'admin-1');

        self::assertSame($explicit, $this->contributed((new PendingRecord)->event('invoice.approved')->by($explicit))->actor);

        $this->expectException(\InvalidArgumentException::class);

        $this->contributed();
    }

    /**
     * With no one signed in and nothing carried, nothing is filled, so the
     * actor stays open for a later contributor.
     *
     * @return void
     */
    public function testNoActorFillsNothing(): void
    {
        $pending  = (new PendingRecord)->event('invoice.approved');
        $snapshot = $this->contributed($pending);

        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->guard);
        self::assertFalse($pending->isActorSettled());
    }

    /**
     * Inside a job with no ambient actor, the carried actor and its guard are
     * filled.
     *
     * @return void
     */
    public function testAJobFallsBackToTheCarriedActor(): void
    {
        $this->carryActor();

        $this->enterAJob();

        $snapshot = $this->contributed();

        self::assertTrue(Reference::of('user', 'user-7')->equals(self::actorOf($snapshot)));
        self::assertSame('admin', $snapshot->guard);
    }

    /**
     * A guard holding a user that cannot be read gives no ambient actor, so a
     * job falls back to the carried one.
     *
     * @return void
     */
    public function testAnUnreadableGuardInAJobFallsBackToTheCarriedActor(): void
    {
        Auth::extend('foreign', static fn (): Guard => new StubForeignGuard(holdsUser: true));

        $config = app(ConfigRepository::class);

        $config->set('auth.guards.foreign', ['driver' => 'foreign', 'provider' => 'users']);
        $config->set('audit-log.actor.guards', ['foreign']);

        $this->carryActor();

        $this->enterAJob();

        self::assertSame('user-7', $this->contributed()->actor?->id);
    }

    /**
     * A command inside a job is still inside the job, so it keeps the carried
     * actor.
     *
     * @return void
     */
    public function testACommandInsideAJobKeepsTheCarriedActor(): void
    {
        $this->carryActor();

        $this->enterAJob();
        $this->frames()->enterCommand(new \stdClass, 'invoices:send');

        self::assertSame('user-7', $this->contributed()->actor?->id);
    }

    /**
     * Outside a job a snapshot left in Context means nothing: it does not say
     * who is acting now.
     *
     * @return void
     */
    public function testACarriedActorIsIgnoredOutsideAJob(): void
    {
        $this->carryActor();

        self::assertNull($this->contributed()->actor);

        $this->frames()->enterRequest(Request::create('/'));

        self::assertNull($this->contributed()->actor);

        $this->frames()->enterCommand(new \stdClass, 'invoices:send');

        self::assertNull($this->contributed()->actor);
    }

    /**
     * A readable guard user wins over the snapshot inside a job.
     *
     * @return void
     */
    public function testTheAmbientActorBeatsTheCarriedOne(): void
    {
        Auth::guard('web')->setUser(self::user());

        $this->carryActor();

        $this->enterAJob();

        $snapshot = $this->contributed();

        self::assertSame('42', $snapshot->actor?->id);
        self::assertSame('web', $snapshot->guard);
    }

    /**
     * Rows of `[hidden keys]`: envelopes a payload could bring back.
     *
     * @return iterable<string, array{0: array<string, array<int, string>|int|string>}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        yield from [
            'a missing guard'       => [[CarriedContext::ACTOR_TYPE => 'user', CarriedContext::ACTOR_ID => 'user-7']],
            'an integer id'         => [[CarriedContext::ACTOR_TYPE => 'user', CarriedContext::ACTOR_ID => 7, CarriedContext::ACTOR_GUARD => 'web']],
            'an array for the type' => [[CarriedContext::ACTOR_TYPE => ['user'], CarriedContext::ACTOR_ID => 'user-7', CarriedContext::ACTOR_GUARD => 'web']],
            'an empty type'         => [[CarriedContext::ACTOR_TYPE => '', CarriedContext::ACTOR_ID => 'user-7', CarriedContext::ACTOR_GUARD => 'web']],
        ];
    }

    /**
     * A malformed envelope is no actor, never an exception and never trusted.
     *
     * @param  array<string, array<int, string>|int|string>  $hidden
     * @return void
     */
    #[DataProvider('provideMalformedEnvelopes')]
    public function testAMalformedEnvelopeIsIgnored(array $hidden): void
    {
        Context::addHidden($hidden);

        $this->enterAJob();

        $snapshot = $this->contributed();

        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->guard);
    }

    /**
     * The carried actor is the one the job's frame kept: what a sync job inside
     * it left in Context afterwards is not read.
     *
     * @return void
     */
    public function testTheFramesActorBeatsWhatASyncJobLeftInContext(): void
    {
        $this->carryActor();
        $this->enterAJob();

        CarriedContext::carryActor(app(Repository::class), new ActorSnapshot(new HeldActor(Reference::of('user', 'user-8')), 'web'));

        $snapshot = $this->contributed();

        self::assertSame('user-7', $snapshot->actor?->id);
        self::assertSame('admin', $snapshot->guard);
    }

    /**
     * A user a guard already held when a job on a worker started is no ambient
     * actor, so the job's own carried actor applies.
     *
     * @return void
     */
    public function testALeftoverGuardUserDoesNotBeatTheCarriedActor(): void
    {
        $user = self::user();

        Auth::guard('web')->setUser($user);

        $this->carryActor();

        $this->frames()->enterJob(new \stdClass, 'App\Jobs\SendInvoice', CarriedContext::actor(app(Repository::class)), ['web' => $user]);

        $snapshot = $this->contributed();

        self::assertSame('user-7', $snapshot->actor?->id);
        self::assertSame('admin', $snapshot->guard);
    }

    /**
     * With no carried actor either, a leftover gives no actor at all.
     *
     * @return void
     */
    public function testALeftoverGuardUserAloneGivesNoActor(): void
    {
        $user = self::user();

        Auth::guard('web')->setUser($user);

        $this->frames()->enterJob(new \stdClass, 'App\Jobs\SendInvoice', null, ['web' => $user]);

        $snapshot = $this->contributed();

        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->guard);
    }

    /**
     * A carried actor stays three strings: it names a type no class has and no
     * table exists for, and it goes through without a query.
     *
     * @return void
     */
    public function testACarriedActorIsNeverResolved(): void
    {
        $this->carryActor();

        $this->enterAJob();

        DB::enableQueryLog();

        self::assertSame('user', $this->contributed()->actor?->type);
        self::assertSame([], DB::getQueryLog());
    }

    /**
     * Neither an ambient nor a carried actor costs a query.
     *
     * @return void
     */
    public function testMakesNoQuery(): void
    {
        DB::enableQueryLog();

        Auth::guard('web')->setUser(self::user());

        $this->contributed();

        self::assertSame([], DB::getQueryLog());
    }

    /**
     * An open actor is filled with the reader's actor, guard, principal, tenant
     * and session.
     *
     * @return void
     */
    public function testFillsTheReadActorWithItsContext(): void
    {
        $this->bindAReader();

        $snapshot = $this->contributed();

        self::assertTrue(Reference::of('identity', 'id-9')->equals(self::actorOf($snapshot)));
        self::assertSame('foreign', $snapshot->guard);
        self::assertSame('p-1', $snapshot->principal?->id);
        self::assertSame('t-1', $snapshot->tenant?->id);
        self::assertSame('session-1', $snapshot->sessionId);
    }

    /**
     * An actor settled to the ambient actor gets its principal, tenant and
     * session but no guard, and an explicit principal is kept.
     *
     * @return void
     */
    public function testAnActorSettledToTheAmbientOneGetsItsContext(): void
    {
        $this->bindAReader();

        $principal = Reference::of('principal', 'p-explicit');
        $snapshot  = $this->contributed((new PendingRecord)->event('invoice.approved')->by(Reference::of('identity', 'id-9'))->asPrincipal($principal));

        self::assertNull($snapshot->guard);
        self::assertSame($principal, $snapshot->principal);
        self::assertSame('t-1', $snapshot->tenant?->id);
        self::assertSame('session-1', $snapshot->sessionId);
    }

    /**
     * An actor settled to anyone else, or to no one, gets none of the ambient
     * actor's context.
     *
     * @return void
     */
    public function testAnActorSettledToSomeoneElseGetsNoContext(): void
    {
        $this->bindAReader();

        foreach ([Reference::of('identity', 'id-other'), null] as $actor) {

            $snapshot = $this->contributed((new PendingRecord)->event('invoice.approved')->by($actor));

            self::assertSame($actor, $snapshot->actor);
            self::assertNull($snapshot->guard);
            self::assertNull($snapshot->principal);
            self::assertNull($snapshot->tenant);
            self::assertNull($snapshot->sessionId);
        }
    }

    /**
     * A job fills the carried actor's context.
     *
     * @return void
     */
    public function testAJobFillsTheCarriedActorsContext(): void
    {
        CarriedContext::carryActor(app(Repository::class), new ActorSnapshot(self::heldWithContext(), 'foreign'));

        $this->enterAJob();

        $snapshot = $this->contributed();

        self::assertSame('id-9', $snapshot->actor?->id);
        self::assertSame('p-1', $snapshot->principal?->id);
        self::assertSame('t-1', $snapshot->tenant?->id);
        self::assertSame('session-1', $snapshot->sessionId);
    }

    /**
     * A user with a key, which is never saved.
     *
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => 42]);
    }

    /**
     * The actor the snapshot holds; a test fails when it holds none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function actorOf(PendingSnapshot $snapshot): Reference
    {
        self::assertInstanceOf(Reference::class, $snapshot->actor);

        return $snapshot->actor;
    }

    /**
     * An actor with a principal, a tenant and a session.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\HeldActor
     */
    private static function heldWithContext(): HeldActor
    {
        return new HeldActor(Reference::of('identity', 'id-9'), Reference::of('principal', 'p-1'), Reference::of('tenant', 't-1'), 'session-1');
    }

    /**
     * Read the actor from a foreign guard holding a user, through a bound
     * reader.
     *
     * @return void
     */
    private function bindAReader(): void
    {
        Auth::extend('foreign', static fn (): Guard => new StubForeignGuard(holdsUser: true));

        $config = app(ConfigRepository::class);

        $config->set('auth.guards.foreign', ['driver' => 'foreign', 'provider' => 'users']);
        $config->set('audit-log.actor.guards', ['foreign']);

        $this->app?->instance(HeldActorReader::class, new StubHeldActorReader(self::heldWithContext()));
    }

    /**
     * The frames of the application.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }

    /**
     * Carry an actor in Context, as a job's payload brings it.
     *
     * @return void
     */
    private function carryActor(): void
    {
        CarriedContext::carryActor(app(Repository::class), new ActorSnapshot(new HeldActor(Reference::of('user', 'user-7')), 'admin'));
    }

    /**
     * Enter a job with what Context carries, as `TrackJobFrames` does once
     * Laravel has hydrated it.
     *
     * @return void
     */
    private function enterAJob(): void
    {
        $this->frames()->enterJob(new \stdClass, 'App\Jobs\SendInvoice', CarriedContext::actor(app(Repository::class)));
    }

    /**
     * What the contributor fills into the builder, or a fresh one.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private function contributed(?PendingRecord $pending = null): PendingSnapshot
    {
        $pending ??= (new PendingRecord)->event('invoice.approved');

        app(ActorContributor::class)->contribute(new Contribution($pending));

        return $pending->snapshot();
    }
}
