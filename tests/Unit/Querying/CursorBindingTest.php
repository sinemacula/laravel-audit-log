<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Querying\CursorBinding;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Querying\Viewer;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for what a page cursor is bound to: the canonical MAC input, its
 * keys sorted, over the version, the log, the viewer, the purpose, the order,
 * the normalised filters, the scope's fingerprint, the page size, the key id
 * and the payload part exactly as sent; and each of them changing the input.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CursorBinding::class)]
final class CursorBindingTest extends TestCase
{
    /** @var string The key id the input is computed for. */
    private const string KEY_ID = 'k2026';

    /** @var string A payload part, as sent. */
    private const string PAYLOAD = 'eyJwb3MiOltdfQ';

    /**
     * The input is the canonical encoding of exactly the bound fields, keys
     * sorted: the normalised filters, the key id, the log as the connection and
     * the table, the order, the payload part as given, the page size, the
     * purpose, the scope's fingerprint, the version and the viewer's type and
     * id.
     *
     * @return void
     */
    public function testTheMacInputIsCanonical(): void
    {
        $expected = '{"filters":{"actor":null,"categories":[],"correlation_id":null,"event_prefix":null,"events":["invoice.approved"],"from":null,'
            . '"outcomes":[],"principal":null,"subject":null,"tenant":null,"to":null},"k":"k2026","log":["testing","audit_log_entries"],'
            . '"order":"occurred_at_desc","payload":"eyJwb3MiOltdfQ","per_page":25,"purpose":"read",'
            . '"scope":"771ba27828b7a815a92a4d3454d3984cee3dcec4fdbfe8e531bc5e63c77895b4","v":1,"viewer":["user","7"]}';

        self::assertSame($expected, self::binding()->macInput(self::KEY_ID, self::PAYLOAD));
        self::assertSame('771ba27828b7a815a92a4d3454d3984cee3dcec4fdbfe8e531bc5e63c77895b4', self::scope()->fingerprint());
    }

    /**
     * The payload part is bound exactly as sent, never decoded, so a part that
     * is no payload at all still gives an input.
     *
     * @return void
     */
    public function testThePayloadIsBoundAsSent(): void
    {
        $input = self::binding()->macInput(self::KEY_ID, 'not-even-base64!');

        self::assertStringContainsString('"payload":"not-even-base64!"', $input);
    }

    /**
     * The same read gives the same input, however its filters were given.
     *
     * @return void
     */
    public function testTheSameReadGivesTheSameInput(): void
    {
        $filters = TrailFilters::none()->withEvents(['invoice.approved', 'invoice.approved']);
        $binding = CursorBinding::for(self::viewer(), ReadPurpose::READ, $filters, self::scope(), 25, 'testing', 'audit_log_entries');

        self::assertSame(self::binding()->macInput(self::KEY_ID, self::PAYLOAD), $binding->macInput(self::KEY_ID, self::PAYLOAD));
    }

    /**
     * Rows of `[the binding, the key id and the payload part]` that differ from
     * the base in exactly one bound field.
     *
     * @return iterable<string, array{0: \Closure(): array{0: \SineMacula\Laravel\AuditLog\Querying\CursorBinding, 1: string, 2: string}}>
     */
    public static function provideBoundFields(): iterable
    {
        $other = static fn (CursorBinding $binding): array => [$binding, self::KEY_ID, self::PAYLOAD];

        yield from [
            'viewer type' => [static fn (): array => $other(self::binding(viewer: Viewer::of(Reference::of('admin', '7'))))],
            'viewer id'   => [static fn (): array => $other(self::binding(viewer: Viewer::of(Reference::of('user', '8'))))],
            'purpose'     => [static fn (): array => $other(self::binding(purpose: ReadPurpose::EXPORT))],
            'filters'     => [static fn (): array => $other(self::binding(filters: TrailFilters::none()->withEvents(['invoice.paid'])))],
            'scope'       => [static fn (): array => $other(self::binding(scope: AccessScope::tenants(Reference::of('team', '2'))))],
            'per page'    => [static fn (): array => $other(self::binding(perPage: 26))],
            'connection'  => [static fn (): array => $other(self::binding(connection: 'reporting'))],
            'table'       => [static fn (): array => $other(self::binding(table: 'other_entries'))],
            'key id'      => [static fn (): array => [self::binding(), 'k2025', self::PAYLOAD]],
            'payload'     => [static fn (): array => [self::binding(), self::KEY_ID, 'eyJwb3MiOltdfR']],
        ];
    }

    /**
     * Each bound field, changed alone, changes the input.
     *
     * @param  \Closure(): array{0: \SineMacula\Laravel\AuditLog\Querying\CursorBinding, 1: string, 2: string}  $other
     * @return void
     */
    #[DataProvider('provideBoundFields')]
    public function testEachBoundFieldChangesTheInput(\Closure $other): void
    {
        [$binding, $keyId, $payload] = $other();

        self::assertNotSame(self::binding()->macInput(self::KEY_ID, self::PAYLOAD), $binding->macInput($keyId, $payload));
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

        return CursorBinding::for($viewer ?? self::viewer(), $purpose, $filters, $scope ?? self::scope(), $perPage, $connection, $table);
    }

    /**
     * The viewer of the base binding.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\Viewer
     */
    private static function viewer(): Viewer
    {
        return Viewer::of(Reference::of('user', '7'));
    }

    /**
     * The scope of the base binding: one tenant.
     *
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     */
    private static function scope(): AccessScope
    {
        return AccessScope::tenants(Reference::of('team', '1'));
    }
}
