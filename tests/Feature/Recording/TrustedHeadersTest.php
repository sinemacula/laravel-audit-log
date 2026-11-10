<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Runtime\InboundIdentifiers;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * End-to-end tests for what an inbound request id or `traceparent` becomes on a
 * stored record: believed only with its own flag on and from a trusted proxy,
 * replaced or ignored when malformed, and never kept, reported or logged when
 * it is not believed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestIdentity::class)]
#[CoversClass(InboundIdentifiers::class)]
#[CoversClass(RequestContributor::class)]
final class TrustedHeadersTest extends TestCase
{
    /** @var string A well-formed inbound request id. */
    private const string REQUEST_ID = 'edge-request-sentinel';

    /** @var string The trace id of the well-formed `traceparent`. */
    private const string TRACE_ID = '0af7651916cd43dd8448eb211c80319c';

    /** @var string A well-formed `traceparent`. */
    private const string TRACEPARENT = '00-' . self::TRACE_ID . '-b7ad6b7169203331-01';

    /** @var string What a malformed flag is refused with. */
    private const string MALFORMED_FLAG = '`audit-log.context.trust_request_id` must be true or false.';

    /** @var string What a UUID version 7 looks like. */
    private const string UUID7 = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /** @var string The peer every request comes from in a test. */
    private const string PEER = '127.0.0.1';

    /** @var string The name the middleware ahead of `TrustProxies` is bound under. */
    private const string BEFORE_TRUST = 'audit-test.before-trust';

    /**
     * Surface a failure inside the route, and give it one to request.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();

        Route::get('/record', static fn (): string => AuditLog::record('invoice.approved')->id);
    }

    /**
     * Put the trusted proxies back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        TrustProxies::flushState();
        Request::setTrustedProxies([], 0);

        parent::tearDown();
    }

    /**
     * With both flags on and no trusted proxy, neither header is believed.
     *
     * @return void
     */
    public function testHeadersAreIgnoredWithoutATrustedProxy(): void
    {
        $this->trust(requestId: true, traceparent: true);

        $entry = $this->recordWith(self::REQUEST_ID, self::TRACEPARENT);

        $this->assertGenerated($entry);
        self::assertNull($entry->trace_id);
    }

    /**
     * From a trusted proxy with both flags off, neither header is believed.
     *
     * @return void
     */
    public function testHeadersAreIgnoredWithTheFlagOff(): void
    {
        TrustProxies::at(self::PEER);

        $entry = $this->recordWith(self::REQUEST_ID, self::TRACEPARENT);

        $this->assertGenerated($entry);
        self::assertNull($entry->trace_id);
    }

    /**
     * With both flags on and a trusted proxy, both headers are believed.
     *
     * @return void
     */
    public function testHeadersAreUsedWithBoth(): void
    {
        TrustProxies::at(self::PEER);

        $this->trust(requestId: true, traceparent: true);

        $entry = $this->recordWith(self::REQUEST_ID, self::TRACEPARENT);

        self::assertSame(self::REQUEST_ID, $entry->request_id);
        self::assertSame(self::TRACE_ID, $entry->trace_id);
    }

    /**
     * Rows of `[trust the request id, trust the traceparent]`: one flag on.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideSingleFlags(): iterable
    {
        yield from [
            'only the request id'  => [true, false],
            'only the traceparent' => [false, true],
        ];
    }

    /**
     * Each flag believes its own header and leaves the other alone.
     *
     * @param  bool  $requestId
     * @param  bool  $traceparent
     * @return void
     */
    #[DataProvider('provideSingleFlags')]
    public function testEachFlagTrustsOnlyItsOwnHeader(bool $requestId, bool $traceparent): void
    {
        TrustProxies::at(self::PEER);

        $this->trust($requestId, $traceparent);

        $entry = $this->recordWith(self::REQUEST_ID, self::TRACEPARENT);

        if ($requestId) {
            self::assertSame(self::REQUEST_ID, $entry->request_id);
            self::assertNull($entry->trace_id);

            return;
        }

        $this->assertGenerated($entry);
        self::assertSame(self::TRACE_ID, $entry->trace_id);
    }

    /**
     * A configured header name is the one believed, and the default name is
     * then a header like any other.
     *
     * @return void
     */
    public function testAConfiguredRequestIdHeaderIsUsed(): void
    {
        TrustProxies::at(self::PEER);

        $this->trust(requestId: true);

        app(ConfigRepository::class)->set('audit-log.context.request_id_header', 'X-Edge-Id');

        $this->withHeaders(['X-Edge-Id' => 'configured-header', 'X-Request-Id' => self::REQUEST_ID])
            ->get('/record')
            ->assertOk();

        self::assertSame('configured-header', AuditEntry::query()->sole()->request_id);
    }

    /**
     * Rows of `[header value]`: what is not 1 to 64 visible ASCII characters.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedRequestIds(): iterable
    {
        yield from [
            'empty'               => [''],
            'one character over'  => [str_repeat('a', 65)],
            'a space'             => ['edge request'],
            'a tab'               => ["edge\trequest"],
            'a control character' => ["edge\x01request"],
            'a delete character'  => ["edge\x7Frequest"],
            'a trailing newline'  => ["edge-request\n"],
            'not ASCII'           => ['requête'],
        ];
    }

    /**
     * A malformed id from a trusted proxy is replaced with a generated one, and
     * the record is still written.
     *
     * @param  string  $requestId
     * @return void
     */
    #[DataProvider('provideMalformedRequestIds')]
    public function testEachMalformedRequestIdIsReplacedByAGeneratedOne(string $requestId): void
    {
        TrustProxies::at(self::PEER);

        $this->trust(requestId: true);

        $this->assertGenerated($this->recordWith($requestId, null));
    }

    /**
     * Rows of `[header value]`: what is not a valid version-`00` `traceparent`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedTraceparents(): iterable
    {
        yield from [
            'empty'             => [''],
            'another version'   => ['01-' . self::TRACE_ID . '-b7ad6b7169203331-01'],
            'an all-zero trace' => ['00-' . str_repeat('0', 32) . '-b7ad6b7169203331-01'],
            'an all-zero span'  => ['00-' . self::TRACE_ID . '-' . str_repeat('0', 16) . '-01'],
            'upper case'        => ['00-' . strtoupper(self::TRACE_ID) . '-b7ad6b7169203331-01'],
            'no flags'          => ['00-' . self::TRACE_ID . '-b7ad6b7169203331'],
            'something after'   => [self::TRACEPARENT . '-extra'],
            'a short trace'     => ['00-0af76519-b7ad6b7169203331-01'],
            'not hexadecimal'   => ['00-' . str_repeat('g', 32) . '-b7ad6b7169203331-01'],
            'a bare trace id'   => [self::TRACE_ID],
        ];
    }

    /**
     * A malformed `traceparent` from a trusted proxy is ignored, and the record
     * is written with no trace id: none is ever generated.
     *
     * @param  string  $traceparent
     * @return void
     */
    #[DataProvider('provideMalformedTraceparents')]
    public function testEachMalformedTraceparentIsIgnored(string $traceparent): void
    {
        TrustProxies::at(self::PEER);

        $this->trust(traceparent: true);

        self::assertNull($this->recordWith(null, $traceparent)->trace_id);
    }

    /**
     * A header that is not believed is not kept as a claim either: no column of
     * the stored row, and nothing in Context, holds it.
     *
     * @return void
     */
    public function testNoClaimedIdIsKept(): void
    {
        $this->trust(requestId: true, traceparent: true);

        $entry = $this->recordWith(self::REQUEST_ID, self::TRACEPARENT);
        $row   = json_encode($entry->getAttributes(), JSON_THROW_ON_ERROR);
        $kept  = json_encode([Context::all(), Context::allHidden()], JSON_THROW_ON_ERROR);

        foreach ([self::REQUEST_ID, self::TRACE_ID] as $claimed) {
            self::assertStringNotContainsString($claimed, $row);
            self::assertStringNotContainsString($claimed, $kept);
        }
    }

    /**
     * A malformed header is dropped in silence, from a trusted proxy too:
     * nothing is reported or logged, so it can reach no log or error tracker.
     *
     * @return void
     */
    public function testAMalformedHeaderIsNeverReported(): void
    {
        $logged = [];

        Exceptions::fake();

        Event::listen(MessageLogged::class, static function (MessageLogged $message) use (&$logged): void {
            $logged[] = $message->message;
        });

        TrustProxies::at(self::PEER);

        $this->trust(requestId: true, traceparent: true);

        $entry = $this->recordWith('malformed header sentinel', 'malformed-traceparent-sentinel');

        Exceptions::assertNothingReported();

        self::assertSame([], $logged);
        self::assertStringNotContainsString('sentinel', json_encode($entry->getAttributes(), JSON_THROW_ON_ERROR));
    }

    /**
     * A header sent twice is not believed, since an edge that overwrites it
     * leaves exactly one value and a client's second value would otherwise
     * decide.
     *
     * @return void
     */
    public function testARepeatedHeaderIsNotBelieved(): void
    {
        TrustProxies::at(self::PEER);

        $this->trust(requestId: true, traceparent: true);

        Route::get('/repeated', static function (Request $request): string {
            $request->headers->set('X-Request-Id', [self::REQUEST_ID, 'second-value']);
            $request->headers->set('traceparent', [self::TRACEPARENT, self::TRACEPARENT]);

            return AuditLog::record('invoice.approved')->id;
        });

        $this->get('/repeated')->assertOk();

        $entry = AuditEntry::query()->sole();

        $this->assertGenerated($entry);
        self::assertNull($entry->trace_id);
    }

    /**
     * A malformed setting fails closed whichever peer the request came from,
     * and what is reported names the setting and not the header.
     *
     * @return void
     */
    public function testAMalformedFlagFailsClosedAndPrintsNoHeader(): void
    {
        $this->withExceptionHandling();

        Exceptions::fake();

        app(ConfigRepository::class)->set('audit-log.context.trust_request_id', 'yes');

        $this->withHeader('X-Request-Id', self::REQUEST_ID)->get('/record')->assertServerError();

        Exceptions::assertReported(static fn (\InvalidArgumentException $exception): bool => $exception->getMessage() === self::MALFORMED_FLAG);

        self::assertSame(0, AuditEntry::query()->count());
    }

    /**
     * A record made in global middleware ahead of `TrustProxies` runs before
     * the proxy is trusted, so the header is not believed and a generated id is
     * kept for the rest of the request, though the proxy is trusted by the time
     * the route records: pinned, and documented.
     *
     * @return void
     */
    public function testARecordBeforeTrustProxiesKeepsAGeneratedId(): void
    {
        TrustProxies::at(self::PEER);

        $this->trust(requestId: true);

        $this->app?->instance(self::BEFORE_TRUST, new class {
            /**
             * Record, then pass the request on.
             *
             * @param  \Illuminate\Http\Request  $request
             * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
             * @return \Symfony\Component\HttpFoundation\Response
             */
            public function handle(Request $request, \Closure $next): Response
            {
                AuditLog::record('invoice.before_trust');

                return $next($request);
            }
        });

        $kernel = app(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        $middleware = $kernel->getGlobalMiddleware();

        array_splice($middleware, 1, 0, [self::BEFORE_TRUST]);

        $kernel->setGlobalMiddleware($middleware);

        $trusted = null;

        Route::get('/after-trust', static function (Request $request) use (&$trusted): string {
            $trusted = $request->isFromTrustedProxy();

            return AuditLog::record('invoice.after_trust')->id;
        });

        $this->withHeaders(['X-Request-Id' => self::REQUEST_ID])->get('/after-trust')->assertOk();

        $before = AuditEntry::query()->where('event', 'invoice.before_trust')->sole();
        $after  = AuditEntry::query()->where('event', 'invoice.after_trust')->sole();

        self::assertTrue($trusted);
        $this->assertGenerated($before);
        self::assertSame($before->request_id, $after->request_id);
    }

    /**
     * Turn the flags on as asked.
     *
     * @param  bool  $requestId
     * @param  bool  $traceparent
     * @return void
     */
    private function trust(bool $requestId = false, bool $traceparent = false): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.context.trust_request_id', $requestId);
        $config->set('audit-log.context.trust_traceparent', $traceparent);
    }

    /**
     * Send a request with the headers given and return the one entry it stored.
     *
     * @param  ?string  $requestId
     * @param  ?string  $traceparent
     * @return \SineMacula\Laravel\AuditLog\Models\AuditEntry
     */
    private function recordWith(?string $requestId, ?string $traceparent): AuditEntry
    {
        $headers = array_filter(['X-Request-Id' => $requestId, 'traceparent' => $traceparent], static fn (?string $value): bool => $value !== null);

        $this->withHeaders($headers)->get('/record')->assertOk();

        return AuditEntry::query()->sole();
    }

    /**
     * Assert the entry's request id is one the package generated.
     *
     * @param  \SineMacula\Laravel\AuditLog\Models\AuditEntry  $entry
     * @return void
     */
    private function assertGenerated(AuditEntry $entry): void
    {
        self::assertMatchesRegularExpression(self::UUID7, (string) $entry->request_id);
    }
}
