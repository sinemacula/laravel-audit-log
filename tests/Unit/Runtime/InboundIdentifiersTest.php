<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\InboundIdentifiers;

/**
 * Unit tests for the inbound identifier validators, which give `null` for bad
 * input and never throw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InboundIdentifiers::class)]
final class InboundIdentifiersTest extends TestCase
{
    /** @var string A valid trace id, from the W3C Trace Context examples. */
    private const string TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';

    /** @var string A valid parent id, from the W3C Trace Context examples. */
    private const string PARENT_ID = '00f067aa0ba902b7';

    /**
     * `InboundIdentifiers` cannot be instantiated: its constructor is private.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(InboundIdentifiers::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(InboundIdentifiers::class, $instance);
    }

    /**
     * A request id is any visible ASCII, a UUID among them, and is kept as
     * given.
     *
     * @return void
     */
    public function testKeepsAValidRequestId(): void
    {
        self::assertSame('019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b', InboundIdentifiers::requestId('019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b'));
        self::assertSame('req/ABC=123+x:y', InboundIdentifiers::requestId('req/ABC=123+x:y'));
    }

    /**
     * Rows of `[request id]`: the bounds of the length and of the visible ASCII
     * range.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequestIdBounds(): iterable
    {
        yield from [
            'one character' => ['a'],
            '64 characters' => [str_repeat('a', 64)],
            'the first'     => ['!'],
            'the last'      => ['~'],
        ];
    }

    /**
     * An id at each bound is kept.
     *
     * @param  string  $requestId
     * @return void
     */
    #[DataProvider('provideRequestIdBounds')]
    public function testKeepsTheBoundsOfARequestId(string $requestId): void
    {
        self::assertSame($requestId, InboundIdentifiers::requestId($requestId));
    }

    /**
     * Rows of `[value]`: anything but 1 to 64 visible ASCII characters.
     *
     * @return iterable<string, array{0: array<never, never>|bool|float|int|string|null}>
     */
    public static function provideMalformedRequestIds(): iterable
    {
        yield from [
            'null'               => [null],
            'empty'              => [''],
            '65 characters'      => [str_repeat('a', 65)],
            'a space'            => ['req 123'],
            'only a space'       => [' '],
            'a tab'              => ["req\t123"],
            'DEL'                => ["req\x7F123"],
            'non-ASCII'          => ['réq'],
            'a trailing newline' => ["req-123\n"],
            'a leading newline'  => ["\nreq-123"],
            'a NUL byte'         => ["req\0123"],
            'an invalid byte'    => ["req\xFF"],
            'an integer'         => [42],
            'a float'            => [4.2],
            'true'               => [true],
            'an array'           => [[]],
        ];
    }

    /**
     * Each malformed request id is ignored, and nothing throws.
     *
     * @param  array<never, never>|bool|float|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideMalformedRequestIds')]
    public function testIgnoresEachMalformedRequestId(array|bool|float|int|string|null $value): void
    {
        self::assertNull(InboundIdentifiers::requestId($value));
    }

    /**
     * A trace id of 32 lower-case hexadecimal digits is kept, one zero digit
     * short of invalid included.
     *
     * @return void
     */
    public function testKeepsAValidTraceId(): void
    {
        self::assertSame(self::TRACE_ID, InboundIdentifiers::traceId(self::TRACE_ID));
        self::assertSame(str_repeat('0', 31) . '1', InboundIdentifiers::traceId(str_repeat('0', 31) . '1'));
    }

    /**
     * Rows of `[value]`: every way of not being a W3C trace id.
     *
     * @return iterable<string, array{0: array<never, never>|int|string|null}>
     */
    public static function provideMalformedTraceIds(): iterable
    {
        yield from [
            'all zero'           => [str_repeat('0', 32)],
            'upper case'         => [strtoupper(self::TRACE_ID)],
            '31 digits'          => [substr(self::TRACE_ID, 1)],
            '33 digits'          => [self::TRACE_ID . 'a'],
            'not hexadecimal'    => [str_repeat('g', 32)],
            'a trailing newline' => [self::TRACE_ID . "\n"],
            'a leading newline'  => ["\n" . self::TRACE_ID],
            'an integer'         => [42],
            'null'               => [null],
            'empty'              => [''],
            'an array'           => [[]],
        ];
    }

    /**
     * Each malformed trace id is ignored, and nothing throws.
     *
     * @param  array<never, never>|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideMalformedTraceIds')]
    public function testIgnoresEachMalformedTraceId(array|int|string|null $value): void
    {
        self::assertNull(InboundIdentifiers::traceId($value));
    }

    /**
     * A valid version-00 header gives its trace id alone, whichever its flags,
     * and one zero digit short of invalid is valid.
     *
     * @return void
     */
    public function testReadsTheTraceIdOfAValidTraceparent(): void
    {
        self::assertSame(self::TRACE_ID, InboundIdentifiers::traceparent(self::header()));
        self::assertSame(self::TRACE_ID, InboundIdentifiers::traceparent('00-' . self::TRACE_ID . '-' . self::PARENT_ID . '-00'));
        self::assertSame(self::TRACE_ID, InboundIdentifiers::traceparent('00-' . self::TRACE_ID . '-' . self::PARENT_ID . '-ff'));
        self::assertSame(self::TRACE_ID, InboundIdentifiers::traceparent('00-' . self::TRACE_ID . '-' . str_repeat('0', 15) . '1-01'));

        $lowest = str_repeat('0', 31) . '1';

        self::assertSame($lowest, InboundIdentifiers::traceparent('00-' . $lowest . '-' . self::PARENT_ID . '-01'));
    }

    /**
     * Rows of `[value]`: every way of not being a full version-00 header.
     *
     * @return iterable<string, array{0: array<never, never>|bool|int|string|null}>
     */
    public static function provideMalformedTraceparents(): iterable
    {
        $trace  = self::TRACE_ID;
        $parent = self::PARENT_ID;

        yield from [
            'version 01'            => ["01-{$trace}-{$parent}-01"],
            'version ff'            => ["ff-{$trace}-{$parent}-01"],
            'all-zero trace id'     => ['00-' . str_repeat('0', 32) . "-{$parent}-01"],
            'all-zero parent id'    => ["00-{$trace}-" . str_repeat('0', 16) . '-01'],
            'upper-case trace id'   => ['00-' . strtoupper($trace) . "-{$parent}-01"],
            'upper-case parent id'  => ["00-{$trace}-" . strtoupper($parent) . '-01'],
            'upper-case flags'      => ["00-{$trace}-{$parent}-0A"],
            'short trace id'        => ['00-' . substr($trace, 1) . "-{$parent}-01"],
            'long trace id'         => ["00-{$trace}a-{$parent}-01"],
            'short parent id'       => ["00-{$trace}-" . substr($parent, 1) . '-01'],
            'long parent id'        => ["00-{$trace}-{$parent}a-01"],
            'one-digit flags'       => ["00-{$trace}-{$parent}-1"],
            'three-digit flags'     => ["00-{$trace}-{$parent}-011"],
            'non-hexadecimal flags' => ["00-{$trace}-{$parent}-zz"],
            'missing part'          => ["00-{$trace}-{$parent}"],
            'extra part'            => ["00-{$trace}-{$parent}-01-extra"],
            'trailing newline'      => ["00-{$trace}-{$parent}-01\n"],
            'leading newline'       => ["\n00-{$trace}-{$parent}-01"],
            'leading space'         => [" 00-{$trace}-{$parent}-01"],
            'trailing space'        => ["00-{$trace}-{$parent}-01 "],
            'a trace id alone'      => [$trace],
            'empty'                 => [''],
            'null'                  => [null],
            'an integer'            => [42],
            'true'                  => [true],
            'an array'              => [[]],
        ];
    }

    /**
     * Each malformed header is ignored, and nothing throws.
     *
     * @param  array<never, never>|bool|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideMalformedTraceparents')]
    public function testIgnoresEachMalformedTraceparent(array|bool|int|string|null $value): void
    {
        self::assertNull(InboundIdentifiers::traceparent($value));
    }

    /**
     * A valid `traceparent`, from the W3C Trace Context examples.
     *
     * @return string
     */
    private static function header(): string
    {
        return '00-' . self::TRACE_ID . '-' . self::PARENT_ID . '-01';
    }
}
