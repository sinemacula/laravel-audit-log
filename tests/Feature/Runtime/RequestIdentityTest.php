<?php

declare(strict_types = 1);

namespace Tests\Feature\Runtime;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Exceptions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Symfony\Component\Console\Input\ArrayInput;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the request id and trace id, and when a header may supply
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestIdentity::class)]
final class RequestIdentityTest extends TestCase
{
    /** @var string The address of the trusted proxy. */
    private const string PROXY = '10.0.0.1';

    /** @var string An address no proxy is trusted at. */
    private const string STRANGER = '203.0.113.9';

    /** @var string The full key of the flag trusting an inbound request id. */
    private const string TRUST_REQUEST_ID = 'audit-log.context.trust_request_id';

    /** @var string The full key of the flag trusting an inbound `traceparent`. */
    private const string TRUST_TRACEPARENT = 'audit-log.context.trust_traceparent';

    /** @var string The full key of the request id's header name. */
    private const string REQUEST_ID_HEADER = 'audit-log.context.request_id_header';

    /** @var string A valid trace id, from the W3C Trace Context examples. */
    private const string TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';

    /** @var string A valid `traceparent` holding that trace id. */
    private const string TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

    /** @var string A well-formed inbound request id. */
    private const string INBOUND_ID = 'edge-request-1';

    /**
     * Bind the runtime state as the provider binds it, which it leaves alone
     * once it binds it itself, and trust one proxy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->scopedIf(ExecutionFrames::class);
        $this->app?->scopedIf(RequestIdentity::class);

        Request::setTrustedProxies([self::PROXY], Request::HEADER_X_FORWARDED_FOR);
    }

    /**
     * Put back the trusted proxies.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Request::setTrustedProxies([], 0);

        parent::tearDown();
    }

    /**
     * With nothing carried and no header, the first call generates a UUID v7.
     *
     * @return void
     */
    public function testGeneratesAUuid7OnFirstUse(): void
    {
        self::assertIsGenerated($this->identity()->requestId());
    }

    /**
     * A generated id takes its time from the clock, to the millisecond, so a
     * frozen clock freezes it.
     *
     * @return void
     */
    public function testTheGeneratedIdUsesTheClock(): void
    {
        $clock = FrozenClock::at('2026-03-04T05:06:07.123Z');

        $this->app?->instance(Clock::class, $clock);

        $requestId = $this->identity()->requestId();

        self::assertSame($clock->now()->getTimestampMs(), hexdec(substr(str_replace('-', '', $requestId), 0, 12)));
    }

    /**
     * Nothing is generated or stored until an id is asked for: resolving the
     * identity, and asking for the trace id, leave Context as it was.
     *
     * @return void
     */
    public function testIsLazy(): void
    {
        $identity = $this->identity();

        $identity->traceId();

        self::assertSame([], Context::allHidden());

        self::assertSame($identity->requestId(), Context::getHidden(CarriedContext::REQUEST_ID));
    }

    /**
     * The id stays the same across calls, and across instances, since it lives
     * in Context.
     *
     * @return void
     */
    public function testIsStableAcrossCalls(): void
    {
        $identity  = $this->identity();
        $requestId = $identity->requestId();

        self::assertSame($requestId, $identity->requestId());

        $this->app?->forgetInstance(RequestIdentity::class);

        self::assertSame($requestId, $this->identity()->requestId());
    }

    /**
     * The id is stored hidden and never visibly, so it stays out of the logs.
     *
     * @return void
     */
    public function testIsStoredHidden(): void
    {
        $requestId = $this->identity()->requestId();

        self::assertSame([CarriedContext::REQUEST_ID => $requestId], Context::allHidden());
        self::assertSame([], Context::all());
    }

    /**
     * An id Context carries is used as it is and generates nothing.
     *
     * @return void
     */
    public function testACarriedIdIsUsed(): void
    {
        Context::addHidden(CarriedContext::REQUEST_ID, 'app:request-1');

        self::assertSame('app:request-1', $this->identity()->requestId());
        self::assertSame([CarriedContext::REQUEST_ID => 'app:request-1'], Context::allHidden());
    }

    /**
     * A carried id beats a trusted header, so the id stays what it was when it
     * was first stored.
     *
     * @return void
     */
    public function testACarriedIdBeatsATrustedHeader(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        Context::addHidden(CarriedContext::REQUEST_ID, 'app:request-1');

        self::assertSame('app:request-1', $this->identity()->requestId());
    }

    /**
     * Only the hidden value counts: a visible value under the same key, which
     * an application's own code might add, is not carried.
     *
     * @return void
     */
    public function testAVisibleValueIsNotCarried(): void
    {
        Context::add(CarriedContext::REQUEST_ID, 'app:visible');
        Context::add(CarriedContext::TRACE_ID, self::TRACE_ID);

        self::assertNotSame('app:visible', $this->identity()->requestId());
        self::assertNull($this->identity()->traceId());
    }

    /**
     * Rows of `[carried value]`: what a queue payload might hold that is no
     * request id.
     *
     * @return iterable<string, array{0: array<int, string>|bool|int|string|null}>
     */
    public static function provideMalformedCarriedIds(): iterable
    {
        yield from [
            'null'          => [null],
            'empty'         => [''],
            '65 characters' => [str_repeat('a', 65)],
            'a space'       => ['app request'],
            'a line feed'   => ["app:request\n"],
            'a NUL'         => ["app\0request"],
            'non-ASCII'     => ['requête'],
            'an integer'    => [42],
            'a boolean'     => [true],
            'an array'      => [['app:request-1']],
        ];
    }

    /**
     * A malformed carried id is ignored and replaced by a generated one, in
     * Context too, so it goes no further.
     *
     * @param  array<int, string>|bool|int|string|null  $carried
     * @return void
     */
    #[DataProvider('provideMalformedCarriedIds')]
    public function testEachMalformedCarriedIdIsReplaced(array|bool|int|string|null $carried): void
    {
        Context::addHidden(CarriedContext::REQUEST_ID, $carried);

        $requestId = $this->identity()->requestId();

        self::assertIsGenerated($requestId);
        self::assertSame($requestId, Context::getHidden(CarriedContext::REQUEST_ID));
    }

    /**
     * A malformed carried id falls through to a trusted header, not straight to
     * a generated id.
     *
     * @return void
     */
    public function testAMalformedCarriedIdFallsThroughToATrustedHeader(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        Context::addHidden(CarriedContext::REQUEST_ID, 'not valid');

        self::assertSame(self::INBOUND_ID, $this->identity()->requestId());
    }

    /**
     * With the flag on and a trusted proxy, the header is the request id, and
     * it is stored hidden.
     *
     * @return void
     */
    public function testATrustedHeaderIsUsed(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        self::assertSame(self::INBOUND_ID, $this->identity()->requestId());
        self::assertSame([CarriedContext::REQUEST_ID => self::INBOUND_ID], Context::allHidden());
    }

    /**
     * A configured header name replaces the default one, which is then just
     * another header.
     *
     * @return void
     */
    public function testAConfiguredHeaderNameIsUsed(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);

        app(ConfigRepository::class)->set(self::REQUEST_ID_HEADER, 'X-Correlation-Id');

        $this->enterRequest(['HTTP_X_CORRELATION_ID' => self::INBOUND_ID, 'HTTP_X_REQUEST_ID' => 'edge-request-2']);

        self::assertSame(self::INBOUND_ID, $this->identity()->requestId());
    }

    /**
     * With the configured header missing, the default header is not read in its
     * place.
     *
     * @return void
     */
    public function testTheDefaultHeaderIsNotReadInPlaceOfAConfiguredOne(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);

        app(ConfigRepository::class)->set(self::REQUEST_ID_HEADER, 'X-Correlation-Id');

        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        self::assertIsGenerated($this->identity()->requestId());
    }

    /**
     * From a trusted proxy but with the flag off, the header is not believed.
     *
     * @return void
     */
    public function testTheHeaderIsIgnoredWithTheFlagOff(): void
    {
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        self::assertIsGenerated($this->identity()->requestId());
    }

    /**
     * With the flag on but from an untrusted peer, the header is not believed,
     * and nothing of it is kept.
     *
     * @return void
     */
    public function testTheHeaderIsIgnoredWithoutATrustedProxy(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['REMOTE_ADDR' => self::STRANGER, 'HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        $requestId = $this->identity()->requestId();

        self::assertIsGenerated($requestId);
        self::assertSame([CarriedContext::REQUEST_ID => $requestId], Context::allHidden());
    }

    /**
     * With no proxy trusted at all, the flag believes nothing.
     *
     * @return void
     */
    public function testTheHeaderIsIgnoredWithNoProxyConfigured(): void
    {
        Request::setTrustedProxies([], 0);

        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID]);

        self::assertIsGenerated($this->identity()->requestId());
    }

    /**
     * Rows of `[header]`: request ids a trusted edge might send that are not
     * well formed.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedHeaders(): iterable
    {
        yield from [
            'empty'         => [''],
            '65 characters' => [str_repeat('a', 65)],
            'a space'       => ['edge request'],
            'a tab'         => ["edge\trequest"],
            'a DEL'         => ["edge\x7Frequest"],
            'non-ASCII'     => ['requête'],
        ];
    }

    /**
     * A malformed header falls through to a generated id, silently.
     *
     * @param  string  $header
     * @return void
     */
    #[DataProvider('provideMalformedHeaders')]
    public function testEachMalformedHeaderIsIgnored(string $header): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => $header]);

        self::assertIsGenerated($this->identity()->requestId());
    }

    /**
     * A header at the bounds of a request id is kept, so a valid one is not
     * mistaken for a malformed one.
     *
     * @return void
     */
    public function testAHeaderOfTheLongestLengthIsUsed(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => str_repeat('a', 64)]);

        self::assertSame(str_repeat('a', 64), $this->identity()->requestId());
    }

    /**
     * A header sent twice is not believed, even when one value is valid or both
     * are the same: an edge that overwrites it sends one.
     *
     * @return void
     */
    public function testTwoHeaderValuesAreIgnored(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);

        foreach ([[self::INBOUND_ID, 'edge-request-2'], [self::INBOUND_ID, self::INBOUND_ID], [self::INBOUND_ID, 'not valid']] as $values) {
            $request = $this->enterRequest();

            $request->headers->set('X-Request-Id', $values);

            $this->identity()->forget();

            self::assertIsGenerated($this->identity()->requestId(), implode(', ', $values));
        }
    }

    /**
     * A header holding no value at all falls through, which protects against a
     * mutation that only refuses more than one.
     *
     * @return void
     */
    public function testAHeaderWithNoValueIsIgnored(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);

        $this->enterRequest()->headers->set('X-Request-Id', []);

        self::assertIsGenerated($this->identity()->requestId());
    }

    /**
     * Beneath a command or a job in the request the header is still found, so a
     * nested record keeps the trusted id.
     *
     * @return void
     */
    public function testAHeaderBeneathACommandIsStillFound(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID, 'HTTP_TRACEPARENT' => self::TRACEPARENT]);

        $this->frames()->enterCommand(new ArrayInput([]), 'invoices:send');
        $this->frames()->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertNull($this->frames()->request());
        self::assertSame(self::INBOUND_ID, $this->identity()->requestId());
        self::assertSame(self::TRACE_ID, $this->identity()->traceId());
    }

    /**
     * Laravel's placeholder console request is never a frame, so its headers
     * are never read.
     *
     * @return void
     */
    public function testNoHeaderIsReadOutsideAnHttpFrame(): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->trust(self::TRUST_TRACEPARENT);

        $placeholder = Request::create('/', server: [
            'REMOTE_ADDR'       => self::PROXY,
            'HTTP_X_REQUEST_ID' => self::INBOUND_ID,
            'HTTP_TRACEPARENT'  => self::TRACEPARENT,
        ]);

        $this->app?->instance('request', $placeholder);

        self::assertIsGenerated($this->identity()->requestId());
        self::assertNull($this->identity()->traceId());

        $this->identity()->forget();

        $this->frames()->enterCommand(new ArrayInput([]), 'invoices:send');

        self::assertIsGenerated($this->identity()->requestId());
        self::assertNull($this->identity()->traceId());
    }

    /**
     * With the flag on and a trusted proxy, the trace id comes from a valid
     * `traceparent`, is stored hidden and stays the same.
     *
     * @return void
     */
    public function testATrustedTraceparentGivesTheTraceId(): void
    {
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_TRACEPARENT' => self::TRACEPARENT]);

        self::assertSame(self::TRACE_ID, $this->identity()->traceId());
        self::assertSame([CarriedContext::TRACE_ID => self::TRACE_ID], Context::allHidden());
        self::assertSame([], Context::all());
        self::assertSame(self::TRACE_ID, $this->identity()->traceId());
    }

    /**
     * From a trusted proxy but with the flag off, a `traceparent` is not
     * believed.
     *
     * @return void
     */
    public function testTheTraceparentIsIgnoredWithTheFlagOff(): void
    {
        $this->enterRequest(['HTTP_TRACEPARENT' => self::TRACEPARENT]);

        self::assertNull($this->identity()->traceId());
        self::assertSame([], Context::allHidden());
    }

    /**
     * With the flag on but from an untrusted peer, a `traceparent` is not
     * believed.
     *
     * @return void
     */
    public function testTheTraceparentIsIgnoredWithoutATrustedProxy(): void
    {
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['REMOTE_ADDR' => self::STRANGER, 'HTTP_TRACEPARENT' => self::TRACEPARENT]);

        self::assertNull($this->identity()->traceId());
        self::assertSame([], Context::allHidden());
    }

    /**
     * Each flag trusts only its own header, which protects against a mutation
     * that reads the other flag.
     *
     * @return void
     */
    public function testEachFlagTrustsOnlyItsOwnHeader(): void
    {
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => self::INBOUND_ID, 'HTTP_TRACEPARENT' => self::TRACEPARENT]);

        self::assertNotSame(self::INBOUND_ID, $this->identity()->requestId());
        self::assertSame(self::TRACE_ID, $this->identity()->traceId());

        $this->identity()->forget();

        app(ConfigRepository::class)->set(self::TRUST_TRACEPARENT, false);

        $this->trust(self::TRUST_REQUEST_ID);

        self::assertSame(self::INBOUND_ID, $this->identity()->requestId());
        self::assertNull($this->identity()->traceId());
    }

    /**
     * Rows of `[header]`: `traceparent` headers a trusted edge might send that
     * are not valid.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedTraceparents(): iterable
    {
        yield from [
            'empty'                 => [''],
            'version 01'            => ['01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'],
            'an all-zero trace id'  => ['00-00000000000000000000000000000000-00f067aa0ba902b7-01'],
            'an all-zero parent id' => ['00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01'],
            'upper-case hex'        => ['00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01'],
            'a short trace id'      => ['00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01'],
            'a missing part'        => ['00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7'],
            'an extra part'         => ['00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-00'],
            'a bare trace id'       => [self::TRACE_ID],
        ];
    }

    /**
     * A malformed `traceparent` gives no trace id, stores nothing and is never
     * an exception.
     *
     * @param  string  $header
     * @return void
     */
    #[DataProvider('provideMalformedTraceparents')]
    public function testEachMalformedTraceparentIsIgnored(string $header): void
    {
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_TRACEPARENT' => $header]);

        self::assertNull($this->identity()->traceId());
        self::assertSame([], Context::allHidden());
    }

    /**
     * A `traceparent` sent twice is not believed, even when both are valid.
     *
     * @return void
     */
    public function testTwoTraceparentsAreIgnored(): void
    {
        $this->trust(self::TRUST_TRACEPARENT);

        $this->enterRequest()->headers->set('traceparent', [self::TRACEPARENT, self::TRACEPARENT]);

        self::assertNull($this->identity()->traceId());
    }

    /**
     * A trace id Context carries is used, and beats a trusted header.
     *
     * @return void
     */
    public function testACarriedTraceIdIsUsed(): void
    {
        $carried = 'a3ce929d0e0e47364bf92f3577b34da6';

        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_TRACEPARENT' => self::TRACEPARENT]);

        Context::addHidden(CarriedContext::TRACE_ID, $carried);

        self::assertSame($carried, $this->identity()->traceId());
    }

    /**
     * Rows of `[carried value]`: what a queue payload might hold that is no
     * trace id.
     *
     * @return iterable<string, array{0: array<int, string>|int|string|null}>
     */
    public static function provideMalformedCarriedTraceIds(): iterable
    {
        yield from [
            'null'          => [null],
            'all zero'      => [str_repeat('0', 32)],
            'upper case'    => ['4BF92F3577B34DA6A3CE929D0E0E4736'],
            '31 digits'     => [str_repeat('a', 31)],
            'a traceparent' => [self::TRACEPARENT],
            'an integer'    => [42],
            'an array'      => [[self::TRACE_ID]],
        ];
    }

    /**
     * A malformed carried trace id is no trace id, and none is generated.
     *
     * @param  array<int, string>|int|string|null  $carried
     * @return void
     */
    #[DataProvider('provideMalformedCarriedTraceIds')]
    public function testEachMalformedCarriedTraceIdIsIgnored(array|int|string|null $carried): void
    {
        Context::addHidden(CarriedContext::TRACE_ID, $carried);

        self::assertNull($this->identity()->traceId());
    }

    /**
     * A malformed carried trace id falls through to a trusted `traceparent`,
     * which replaces it.
     *
     * @return void
     */
    public function testAMalformedCarriedTraceIdFallsThroughToATrustedHeader(): void
    {
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_TRACEPARENT' => self::TRACEPARENT]);

        Context::addHidden(CarriedContext::TRACE_ID, 'not valid');

        self::assertSame(self::TRACE_ID, $this->identity()->traceId());
        self::assertSame(self::TRACE_ID, Context::getHidden(CarriedContext::TRACE_ID));
    }

    /**
     * With nothing carried and no header there is no trace id: none is ever
     * generated, and asking stores nothing.
     *
     * @return void
     */
    public function testNoTraceIdIsNull(): void
    {
        $this->enterRequest();

        self::assertNull($this->identity()->traceId());
        self::assertSame([], Context::allHidden());
    }

    /**
     * Forgetting removes the five package keys and nothing else, visible or
     * hidden.
     *
     * @return void
     */
    public function testForgetRemovesOnlyThePackagesKeys(): void
    {
        Context::add('tenant', 'acme');
        Context::add(CarriedContext::REQUEST_ID, 'app:visible');
        Context::addHidden([
            'app.secret'                => 'kept',
            CarriedContext::REQUEST_ID  => 'app:request-1',
            CarriedContext::TRACE_ID    => self::TRACE_ID,
            CarriedContext::ACTOR_TYPE  => 'App\Models\User',
            CarriedContext::ACTOR_ID    => '42',
            CarriedContext::ACTOR_GUARD => 'web',
        ]);

        $this->identity()->forget();

        self::assertSame(['tenant' => 'acme', CarriedContext::REQUEST_ID => 'app:visible'], Context::all());
        self::assertSame(['app.secret' => 'kept'], Context::allHidden());
    }

    /**
     * After forgetting, the next id is a new one and the frames are untouched.
     *
     * @return void
     */
    public function testAForgottenIdIsGeneratedAfresh(): void
    {
        $request = $this->enterRequest();
        $earlier = $this->identity()->requestId();

        $this->identity()->forget();

        self::assertNotSame($earlier, $this->identity()->requestId());
        self::assertSame($request, $this->frames()->request());
    }

    /**
     * A malformed header is never reported and never kept: only the generated
     * id reaches Context.
     *
     * @return void
     */
    public function testNoMalformedHeaderIsReported(): void
    {
        Exceptions::fake();

        $this->trust(self::TRUST_REQUEST_ID);
        $this->trust(self::TRUST_TRACEPARENT);
        $this->enterRequest(['HTTP_X_REQUEST_ID' => 'claimed request', 'HTTP_TRACEPARENT' => 'claimed-parent']);

        $requestId = $this->identity()->requestId();

        self::assertNull($this->identity()->traceId());
        self::assertSame([CarriedContext::REQUEST_ID => $requestId], Context::allHidden());

        Exceptions::assertNothingReported();
    }

    /**
     * Rows of `[setting, value, whether the request id is asked for, the
     * message]`: each malformed header setting.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: bool, 3: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'the request id flag'  => [self::TRUST_REQUEST_ID, 'yes', true, '`audit-log.context.trust_request_id` must be true or false.'],
            'the traceparent flag' => [self::TRUST_TRACEPARENT, 1, false, '`audit-log.context.trust_traceparent` must be true or false.'],
            'the header name'      => [self::REQUEST_ID_HEADER, 'X Request Id', true, '`audit-log.context.request_id_header` must be a header name of 1 to 64 characters.'],
        ];
    }

    /**
     * A malformed setting is a refusal rather than a fall-through.
     *
     * @param  string  $setting
     * @param  int|string  $value
     * @param  bool  $asksForRequestId
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMalformedTrustSettingIsRefused(string $setting, int|string $value, bool $asksForRequestId, string $message): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->trust(self::TRUST_TRACEPARENT);

        app(ConfigRepository::class)->set($setting, $value);

        $this->enterRequest();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $asksForRequestId ? $this->identity()->requestId() : $this->identity()->traceId();
    }

    /**
     * A malformed setting is refused whichever peer the request came from, so
     * it fails on the first request rather than only on the edge's.
     *
     * @param  string  $setting
     * @param  int|string  $value
     * @param  bool  $asksForRequestId
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMalformedTrustSettingIsRefusedFromAnyPeer(string $setting, int|string $value, bool $asksForRequestId, string $message): void
    {
        $this->trust(self::TRUST_REQUEST_ID);
        $this->trust(self::TRUST_TRACEPARENT);

        app(ConfigRepository::class)->set($setting, $value);

        $this->enterRequest(['REMOTE_ADDR' => self::STRANGER]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $asksForRequestId ? $this->identity()->requestId() : $this->identity()->traceId();
    }

    /**
     * An id first made inside `Context::scope()` outlives it, though the scope
     * restores hidden Context as it ends.
     *
     * @return void
     */
    public function testAnIdFirstMadeInsideAContextScopeOutlivesIt(): void
    {
        $identity = $this->identity();

        $inside = Context::scope(static fn (): string => $identity->requestId());

        self::assertNull(Context::getHidden(CarriedContext::REQUEST_ID));
        self::assertSame($inside, $identity->requestId());
        self::assertSame($inside, Context::getHidden(CarriedContext::REQUEST_ID));
    }

    /**
     * A trace id first found inside `Context::scope()` outlives it too.
     *
     * @return void
     */
    public function testATraceIdFirstFoundInsideAContextScopeOutlivesIt(): void
    {
        Request::setTrustedProxies([self::PROXY], Request::HEADER_X_FORWARDED_FOR);

        $this->trust(self::TRUST_TRACEPARENT);

        $this->enterRequest(['REMOTE_ADDR' => self::PROXY, 'HTTP_TRACEPARENT' => self::TRACEPARENT]);

        $identity = $this->identity();

        self::assertSame(self::TRACE_ID, Context::scope(static fn (): ?string => $identity->traceId()));
        self::assertNull(Context::getHidden(CarriedContext::TRACE_ID));

        Request::setTrustedProxies([], 0);

        self::assertSame(self::TRACE_ID, $identity->traceId());
        self::assertSame(self::TRACE_ID, Context::getHidden(CarriedContext::TRACE_ID));
    }

    /**
     * Context comes before what is remembered, so a job's hydrated ids win.
     *
     * @return void
     */
    public function testContextBeatsARememberedId(): void
    {
        $identity = $this->identity();

        $identity->requestId();

        Context::addHidden(CarriedContext::REQUEST_ID, 'app:hydrated');
        Context::addHidden(CarriedContext::TRACE_ID, self::TRACE_ID);

        self::assertSame('app:hydrated', $identity->requestId());
        self::assertSame(self::TRACE_ID, $identity->traceId());
    }

    /**
     * An id read from Context is remembered as well, so losing it from Context
     * loses nothing.
     *
     * @return void
     */
    public function testAnIdFoundInContextIsRemembered(): void
    {
        Context::addHidden(CarriedContext::REQUEST_ID, 'app:hydrated');
        Context::addHidden(CarriedContext::TRACE_ID, self::TRACE_ID);

        $identity = $this->identity();

        self::assertSame('app:hydrated', $identity->requestId());
        self::assertSame(self::TRACE_ID, $identity->traceId());

        Context::forgetHidden([CarriedContext::REQUEST_ID, CarriedContext::TRACE_ID]);

        self::assertSame('app:hydrated', $identity->requestId());
        self::assertSame(self::TRACE_ID, $identity->traceId());
    }

    /**
     * `forget()` forgets what is remembered as well as what Context holds.
     *
     * @return void
     */
    public function testForgetForgetsWhatIsRemembered(): void
    {
        $identity = $this->identity();

        Context::addHidden(CarriedContext::TRACE_ID, self::TRACE_ID);

        $first = $identity->requestId();

        $identity->traceId();
        $identity->forget();

        self::assertNotSame($first, $identity->requestId());
        self::assertNull($identity->traceId());
    }

    /**
     * `forgetResolved()` forgets what is remembered and leaves Context as it
     * is.
     *
     * @return void
     */
    public function testForgetResolvedLeavesContextAlone(): void
    {
        $identity = $this->identity();

        Context::addHidden(CarriedContext::TRACE_ID, self::TRACE_ID);

        $first = $identity->requestId();

        $identity->traceId();
        $identity->forgetResolved();

        self::assertSame($first, Context::getHidden(CarriedContext::REQUEST_ID));
        self::assertSame(self::TRACE_ID, Context::getHidden(CarriedContext::TRACE_ID));

        Context::forgetHidden([CarriedContext::REQUEST_ID, CarriedContext::TRACE_ID]);

        self::assertNotSame($first, $identity->requestId());
        self::assertNull($identity->traceId());
    }

    /**
     * Assert the id is one the package generated: a UUID v7, in the canonical
     * form, so a header's value or a carried one can never pass for it.
     *
     * @param  string  $requestId
     * @param  string  $message
     * @return void
     */
    private static function assertIsGenerated(string $requestId, string $message = ''): void
    {
        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $requestId, $message);
    }

    /**
     * Enter a request's frame, by default from the trusted proxy.
     *
     * @param  array<string, string>  $server
     * @return \Illuminate\Http\Request
     */
    private function enterRequest(array $server = []): Request
    {
        $request = Request::create('/invoices', server: [...['REMOTE_ADDR' => self::PROXY], ...$server]);

        $this->frames()->enterRequest($request);

        return $request;
    }

    /**
     * Turn the flag on.
     *
     * @param  string  $flag
     * @return void
     */
    private function trust(string $flag): void
    {
        app(ConfigRepository::class)->set($flag, true);
    }

    /**
     * The identity of the current container.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\RequestIdentity
     */
    private function identity(): RequestIdentity
    {
        return app(RequestIdentity::class);
    }

    /**
     * The frames of the current container.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames
     */
    private function frames(): ExecutionFrames
    {
        return app(ExecutionFrames::class);
    }
}
