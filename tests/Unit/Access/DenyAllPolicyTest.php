<?php

declare(strict_types = 1);

namespace Tests\Unit\Access;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Unit tests for the access policy the package binds by default: every viewer,
 * a model or a reference, is denied for every purpose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DenyAllPolicy::class)]
final class DenyAllPolicyTest extends TestCase
{
    /**
     * Rows of `[viewer, purpose]`: a model viewer and a reference viewer, each
     * for every purpose.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference, 1: \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideViewersAndPurposes(): iterable
    {
        foreach (ReadPurpose::cases() as $purpose) {
            yield "a model, to {$purpose->value}" => [(new StubAuthUser)->forceFill(['id' => 7]), $purpose];
            yield "a reference, to {$purpose->value}" => [Reference::of('user', '7'), $purpose];
        }
    }

    /**
     * Whoever the viewer and whatever the purpose, the scope is denied, and is
     * the one form every denied scope has.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|\SineMacula\Laravel\AuditLog\Records\Reference  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return void
     */
    #[DataProvider('provideViewersAndPurposes')]
    public function testEveryViewerAndPurposeIsDenied(Authenticatable|Reference $viewer, ReadPurpose $purpose): void
    {
        $scope = (new DenyAllPolicy)->scope($viewer, $purpose);

        self::assertTrue($scope->isDenied());
        self::assertSame(AccessScope::none()->toArray(), $scope->toArray());
    }

    /**
     * The policy is an access policy, so the package can bind it to the
     * contract.
     *
     * @return void
     */
    public function testItIsAnAccessPolicy(): void
    {
        self::assertInstanceOf(AuditAccessPolicy::class, new DenyAllPolicy);
    }
}
