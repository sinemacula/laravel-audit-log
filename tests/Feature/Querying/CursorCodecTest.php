<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\CursorBinding;
use SineMacula\Laravel\AuditLog\Querying\CursorCodec;
use SineMacula\Laravel\AuditLog\Querying\InvalidCursorException;
use SineMacula\Laravel\AuditLog\Querying\Position;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Querying\Viewer;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\TestCase;

/**
 * Feature tests for the page cursor's format, binding and refusals.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CursorCodec::class)]
final class CursorCodecTest extends TestCase
{
    /** @var string The secret of the ring's signing key: 32 bytes. */
    private const string SECRET = 'a-cursor-test-secret-of-32-bytes';

    /** @var string The secret of an older key of the ring: 32 bytes. */
    private const string OLD_SECRET = 'an-older-cursor-secret-32-bytes!';

    /** @var string The time of the position a cursor holds. */
    private const string TIME = '2026-11-01T12:00:00.123456Z';

    /** @var string The entry id of the position a cursor holds. */
    private const string ID = '0192f0c1-7e2a-7b3c-8d4e-5f6a7b8c9d0e';

    /** @var string The one message of every refusal. */
    private const string REFUSED = 'The cursor was refused.';

    /**
     * Use an explicit ring of two keys, the newer signing.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->useRing('k2026');
    }

    /**
     * A cursor is `v1`, key id, payload and MAC, each unpadded base64url.
     *
     * @return void
     */
    public function testACursorIsVersionKeyPayloadAndMac(): void
    {
        $cursor = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));
        $parts  = explode('.', $cursor);

        self::assertCount(4, $parts);
        self::assertSame('v1', $parts[0]);
        self::assertSame(self::encode('k2026'), $parts[1]);
        self::assertSame(self::encode('{"pos":["' . self::TIME . '","' . self::ID . '"]}'), $parts[2]);
        self::assertSame(self::mac(self::SECRET, self::binding()->macInput('k2026', $parts[2])), $parts[3]);
        self::assertSame(1, preg_match('/\Av1(\.[A-Za-z0-9_-]+){3}\z/', $cursor));
        self::assertSame('sinemacula/audit-log:cursor:v1', CursorCodec::DERIVATION_INFO);
        self::assertSame('v1', CursorCodec::VERSION);
        self::assertSame(512, CursorCodec::MAX_BYTES);
    }

    /**
     * A cursor issued for a read opens for the same read, to its position.
     *
     * @return void
     */
    public function testAnIssuedCursorOpens(): void
    {
        $cursor   = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));
        $position = $this->codec()->open($cursor, self::binding());

        self::assertSame([self::TIME, self::ID], $position->toArray());
    }

    /**
     * A derived ring signs with `app.key` and still opens under a previous key.
     *
     * @return void
     */
    public function testADerivedRingIssuesAndOpens(): void
    {
        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);

        $config->set('audit-log.integrity', ['keys' => [], 'current' => null]);

        $old    = $config->string('app.key');
        $cursor = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));

        self::assertSame(1, preg_match('/\Ad[0-9a-f]{16}\z/', (string) base64_decode(strtr(explode('.', $cursor)[1], '-_', '+/'), true)));

        $config->set('app.key', 'base64:' . base64_encode('a-rotated-application-key-32-byt'));
        $config->set('app.previous_keys', [$old]);

        self::assertSame(self::ID, $this->codec()->open($cursor, self::binding())->id);
        self::assertNotSame(explode('.', $cursor)[1], explode('.', $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID)))[1]);
    }

    /**
     * A cursor over 512 bytes is refused before reaching the ring, which is
     * made malformed to show it.
     *
     * @return void
     */
    public function testRefusesMoreThan512Bytes(): void
    {
        $this->breakRing();

        $head    = 'v1.' . self::encode('k2026') . '.';
        $tail    = '.' . self::encode(str_repeat("\0", 32));
        $exactly = $head . str_repeat('A', 512 - strlen($head) - strlen($tail)) . $tail;

        self::assertSame(512, strlen($exactly));

        try {
            $this->codec()->open($exactly, self::binding());
            self::fail('Expected the malformed ring to be read.');
        } catch (\InvalidArgumentException $exception) {
            self::assertNotInstanceOf(InvalidCursorException::class, $exception);
        }

        $over = $head . str_repeat('A', 513 - strlen($head) - strlen($tail)) . $tail;

        $this->expectException(InvalidCursorException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $this->codec()->open($over, self::binding());
    }

    /**
     * Rows of `[cursor]`: cursors of the wrong shape.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedShapes(): iterable
    {
        $key = self::encode('k2026');
        $mac = self::encode(str_repeat("\1", 32));
        $pay = self::encode('{"pos":["' . self::TIME . '","' . self::ID . '"]}');

        yield from [
            'empty'                         => [''],
            'no prefix'                     => ["{$key}.{$pay}.{$mac}"],
            'another version'               => ["v2.{$key}.{$pay}.{$mac}"],
            'an upper-case version'         => ["V1.{$key}.{$pay}.{$mac}"],
            'three parts'                   => ["v1.{$key}.{$pay}"],
            'five parts'                    => ["v1.{$key}.{$pay}.{$mac}.{$mac}"],
            'an empty key id'               => ["v1..{$pay}.{$mac}"],
            'an empty payload'              => ["v1.{$key}..{$mac}"],
            'an empty MAC'                  => ["v1.{$key}.{$pay}."],
            'padding'                       => ["v1.{$key}=.{$pay}.{$mac}"],
            'the standard alphabet'         => ["v1.{$key}.{$pay}+/.{$mac}"],
            'a space'                       => ["v1.{$key}.{$pay}.{$mac} "],
            'a key id not strictly encoded' => ['v1.azIwMjX.' . $pay . '.' . $mac],
            'a key id outside its pattern'  => ['v1.' . self::encode('-k2026') . ".{$pay}.{$mac}"],
            'a key id over 32 characters'   => ['v1.' . self::encode(str_repeat('k', 33)) . ".{$pay}.{$mac}"],
            'a key id with a control byte'  => ['v1.' . self::encode("k2026\n") . ".{$pay}.{$mac}"],
        ];
    }

    /**
     * A malformed cursor is refused with the one message before any key lookup.
     *
     * @param  string  $cursor
     * @return void
     */
    #[DataProvider('provideMalformedShapes')]
    public function testRefusesAMalformedShape(string $cursor): void
    {
        $this->breakRing();

        $this->expectException(InvalidCursorException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $this->codec()->open($cursor, self::binding());
    }

    /**
     * Rows of `[MAC part]`: MAC parts that do not decode strictly to 32 bytes.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedMacs(): iterable
    {
        yield from [
            '31 bytes'             => [self::encode(str_repeat("\1", 31))],
            '33 bytes'             => [self::encode(str_repeat("\1", 33))],
            'not strictly encoded' => [substr(self::encode(str_repeat("\1", 32)), 0, -1) . 'F'],
        ];
    }

    /**
     * A MAC part that is not 32 strictly encoded bytes is refused.
     *
     * @param  string  $mac
     * @return void
     */
    #[DataProvider('provideMalformedMacs')]
    public function testRefusesAMalformedMac(string $mac): void
    {
        $this->expectException(InvalidCursorException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $this->codec()->open('v1.' . self::encode('k2026') . '.' . self::encode('{}') . '.' . $mac, self::binding());
    }

    /**
     * Rows of `[payload part]`: payloads that are not exactly a position's.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedPayloads(): iterable
    {
        $position = '["' . self::TIME . '","' . self::ID . '"]';

        yield from [
            'not JSON'               => [self::encode('pos')],
            'not strictly encoded'   => ['e31'],
            'invalid UTF-8'          => [self::encode("{\"pos\":[\"\xff\",\"" . self::ID . '"]}')],
            'a list'                 => [self::encode($position)],
            'a string'               => [self::encode('"pos"')],
            'an empty map'           => [self::encode('{}')],
            'extra key'              => [self::encode('{"k":"k2026","pos":' . $position . '}')],
            'another key'            => [self::encode('{"position":' . $position . '}')],
            'a third nesting level'  => [self::encode('{"pos":[["' . self::TIME . '"],"' . self::ID . '"]}')],
            'a map for the position' => [self::encode('{"pos":{"0":"' . self::TIME . '","1":"' . self::ID . '"}}')],
            'one member'             => [self::encode('{"pos":["' . self::TIME . '"]}')],
            'three members'          => [self::encode('{"pos":["' . self::TIME . '","' . self::ID . '","x"]}')],
            'a number for the time'  => [self::encode('{"pos":[1,"' . self::ID . '"]}')],
            'null for the id'        => [self::encode('{"pos":["' . self::TIME . '",null]}')],
            'not canonical'          => [self::encode('{"pos": ' . $position . '}')],
            'an escaped slash'       => [self::encode('{"pos":["' . self::TIME . '","' . self::ID . '\/"]}')],
            'a time not an instant'  => [self::encode('{"pos":["2026-11-01 12:00:00","' . self::ID . '"]}')],
            'an upper-case id'       => [self::encode('{"pos":["' . self::TIME . '","' . strtoupper(self::ID) . '"]}')],
        ];
    }

    /**
     * A payload under a matching MAC is refused unless exactly a position.
     *
     * @param  string  $payload
     * @return void
     */
    #[DataProvider('provideMalformedPayloads')]
    public function testRefusesAMalformedPayloadEvenUnderAMatchingMac(string $payload): void
    {
        $cursor = 'v1.' . self::encode('k2026') . '.' . $payload . '.' . self::mac(self::SECRET, self::binding()->macInput('k2026', $payload));

        $this->expectException(InvalidCursorException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $this->codec()->open($cursor, self::binding());
    }

    /**
     * A payload encoded here opens, so the check above cannot refuse all.
     *
     * @return void
     */
    public function testAPayloadEncodedElsewhereOpens(): void
    {
        $payload = self::encode('{"pos":["' . self::TIME . '","' . self::ID . '"]}');
        $cursor  = 'v1.' . self::encode('k2025') . '.' . $payload . '.' . self::mac(self::OLD_SECRET, self::binding()->macInput('k2025', $payload));

        self::assertSame([self::TIME, self::ID], $this->codec()->open($cursor, self::binding())->toArray());
    }

    /**
     * A cursor naming an unknown key is refused with the one message.
     *
     * @return void
     */
    public function testAnUnknownKeyIsRefusedLikeAnyOther(): void
    {
        $payload = self::encode('{"pos":["' . self::TIME . '","' . self::ID . '"]}');
        $cursor  = 'v1.' . self::encode('k2024') . '.' . $payload . '.' . self::mac(self::SECRET, self::binding()->macInput('k2024', $payload));

        try {
            $this->codec()->open($cursor, self::binding());
            self::fail('Expected the cursor to be refused.');
        } catch (InvalidCursorException $exception) {
            self::assertSame(self::REFUSED, $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * A swapped payload, an altered MAC or one under the raw secret is refused.
     *
     * @return void
     */
    public function testATamperedPayloadIsRefusedByItsMac(): void
    {
        $parts = explode('.', $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID)));
        $other = self::encode('{"pos":["' . self::TIME . '","0192f0c1-7e2a-7b3c-8d4e-5f6a7b8c9d0f"]}');
        $mac   = (string) base64_decode(strtr($parts[3], '-_', '+/'), true);
        $raw   = rtrim(strtr(base64_encode(hash_hmac('sha256', self::binding()->macInput('k2026', $parts[2]), self::SECRET, true)), '+/', '-_'), '=');

        $tampered = [
            implode('.', [$parts[0], $parts[1], $other, $parts[3]]),
            implode('.', [$parts[0], $parts[1], $parts[2], self::encode(($mac[0] ^ "\1") . substr($mac, 1))]),
            implode('.', [$parts[0], $parts[1], $parts[2], $raw]),
            implode('.', [$parts[0], self::encode('k2025'), $parts[2], $parts[3]]),
        ];

        foreach ($tampered as $index => $cursor) {
            try {
                $this->codec()->open($cursor, self::binding());
                self::fail("Expected tampered cursor {$index} to be refused.");
            } catch (InvalidCursorException $exception) {
                self::assertSame(self::REFUSED, $exception->getMessage(), "Tampered cursor {$index}.");
            }
        }
    }

    /**
     * Rows of `[another binding]`: reads differing in exactly one bound field.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Querying\CursorBinding}>
     */
    public static function provideOtherBindings(): iterable
    {
        yield from [
            'viewer type' => [static fn (): CursorBinding => self::binding(viewer: Viewer::of(Reference::of('admin', '7')))],
            'viewer id'   => [static fn (): CursorBinding => self::binding(viewer: Viewer::of(Reference::of('user', '8')))],
            'purpose'     => [static fn (): CursorBinding => self::binding(purpose: ReadPurpose::COUNT)],
            'filters'     => [static fn (): CursorBinding => self::binding(filters: TrailFilters::none()->withEvents(['invoice.paid']))],
            'no filters'  => [static fn (): CursorBinding => self::binding(filters: TrailFilters::none())],
            'scope'       => [static fn (): CursorBinding => self::binding(scope: AccessScope::tenants(Reference::of('team', '1'), Reference::of('team', '2')))],
            'per page'    => [static fn (): CursorBinding => self::binding(perPage: 26)],
            'connection'  => [static fn (): CursorBinding => self::binding(connection: 'reporting')],
            'table'       => [static fn (): CursorBinding => self::binding(table: 'other_entries')],
        ];
    }

    /**
     * A cursor opens for no read but its own.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Querying\CursorBinding  $other
     * @return void
     */
    #[DataProvider('provideOtherBindings')]
    public function testEachBoundFieldRefusesAnotherBinding(\Closure $other): void
    {
        $cursor = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));

        $this->expectException(InvalidCursorException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $this->codec()->open($cursor, $other());
    }

    /**
     * Opening a cursor, accepted or refused, makes no query.
     *
     * @return void
     */
    public function testOpeningMakesNoQuery(): void
    {
        $queries = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $cursor = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));

        $this->codec()->open($cursor, self::binding());

        try {
            $this->codec()->open($cursor, self::binding(perPage: 10));
        } catch (InvalidCursorException) {
            // Refused, as expected; only the queries matter here
        }

        self::assertSame([], $queries);
    }

    /**
     * A cursor from a previous key opens until the key leaves the ring.
     *
     * @return void
     */
    public function testACursorFromAPreviousKeyStillOpens(): void
    {
        $this->useRing('k2025');

        $cursor = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));

        self::assertSame(self::encode('k2025'), explode('.', $cursor)[1]);

        $this->useRing('k2026');

        self::assertSame(self::ID, $this->codec()->open($cursor, self::binding())->id);
        self::assertSame(self::encode('k2026'), explode('.', $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID)))[1]);

        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);

        $config->set('audit-log.integrity.keys', ['k2026' => self::SECRET]);

        $this->expectException(InvalidCursorException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $this->codec()->open($cursor, self::binding());
    }

    /**
     * Every refusal has the one message, no code and no previous exception.
     *
     * @return void
     */
    public function testTheMessageIsUniform(): void
    {
        $valid   = $this->codec()->issue(self::binding(), new Position(self::TIME, self::ID));
        $parts   = explode('.', $valid);
        $payload = self::encode('{"pos":["' . self::TIME . '","nope"]}');

        $refused = [
            'too long'           => str_repeat('A', 513),
            'malformed'          => 'v1.' . $parts[1],
            'unknown key'        => implode('.', ['v1', self::encode('k2024'), $parts[2], $parts[3]]),
            'short MAC'          => implode('.', ['v1', $parts[1], $parts[2], self::encode('short')]),
            'mismatched MAC'     => implode('.', ['v1', $parts[1], $payload, $parts[3]]),
            'malformed position' => implode('.', ['v1', $parts[1], $payload, self::mac(self::SECRET, self::binding()->macInput('k2026', $payload))]),
        ];

        foreach ($refused as $cause => $cursor) {
            try {
                $this->codec()->open($cursor, self::binding());
                self::fail("Expected the cursor ({$cause}) to be refused.");
            } catch (InvalidCursorException $exception) {
                self::assertSame([self::REFUSED, 0, null], [$exception->getMessage(), $exception->getCode(), $exception->getPrevious()], $cause);
            }
        }
    }

    /**
     * The codec, over the container's ring.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\CursorCodec
     */
    private function codec(): CursorCodec
    {
        $ring = $this->app?->make(KeyRing::class);

        self::assertInstanceOf(KeyRing::class, $ring);

        return new CursorCodec($ring);
    }

    /**
     * Configure an explicit ring of the two keys, the one with the id signing.
     *
     * @param  string  $current
     * @return void
     */
    private function useRing(string $current): void
    {
        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);

        $config->set('audit-log.integrity', ['keys' => ['k2025' => self::OLD_SECRET, 'k2026' => self::SECRET], 'current' => $current]);
    }

    /**
     * Configure a ring that fails closed when read: a current key and no keys.
     *
     * @return void
     */
    private function breakRing(): void
    {
        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);

        $config->set('audit-log.integrity', ['keys' => [], 'current' => 'k2026']);
    }

    /**
     * The base binding, or one with a field replaced.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  int  $perPage
     * @param  string  $connection
     * @param  string  $table
     * @return \SineMacula\Laravel\AuditLog\Querying\CursorBinding
     */
    private static function binding(
        #[\SensitiveParameter]
        ?Viewer $viewer = null,
        ReadPurpose $purpose = ReadPurpose::READ,
        ?TrailFilters $filters = null,
        ?AccessScope $scope = null,
        int $perPage = 25,
        string $connection = 'testing',
        string $table = 'audit_log_entries',
    ): CursorBinding {
        $filters ??= TrailFilters::none()->withEvents(['invoice.approved']);
        $scope   ??= AccessScope::tenants(Reference::of('team', '1'));

        return CursorBinding::for($viewer ?? Viewer::of(Reference::of('user', '7')), $purpose, $filters, $scope, $perPage, $connection, $table);
    }

    /**
     * The MAC part: HMAC-SHA256 under HKDF-SHA256 of the secret, as base64url.
     *
     * @param  string  $secret
     * @param  string  $input
     * @return string
     */
    private static function mac(#[\SensitiveParameter] string $secret, string $input): string
    {
        $key = hash_hkdf('sha256', $secret, 32, 'sinemacula/audit-log:cursor:v1', '');

        return self::encode(hash_hmac('sha256', $input, $key, true));
    }

    /**
     * Encode bytes as unpadded base64url.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
