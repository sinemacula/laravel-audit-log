<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\MembershipDigest;

/**
 * Unit tests for the streaming membership digest: the SHA-256 of each id and a
 * line feed in the order given, the digest of the empty set, the order bound
 * into it, and a digest taken once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MembershipDigest::class)]
final class MembershipDigestTest extends TestCase
{
    /** @var string The first id of every test. */
    private const string FIRST = '01932b4e-a000-7000-8000-000000000001';

    /** @var string The second id of every test. */
    private const string SECOND = '01932b4e-a000-7000-8000-000000000002';

    /**
     * The digest is the lower-case hex SHA-256 of each id followed by a line
     * feed, in the order the ids were added, so an auditor recomputes it from
     * the file's ids alone.
     *
     * @return void
     */
    public function testTheDigestIsOfEachIdAndALineFeedInOrder(): void
    {
        $digest = new MembershipDigest;

        $digest->add(self::FIRST);
        $digest->add(self::SECOND);

        self::assertSame(hash('sha256', self::FIRST . "\n" . self::SECOND . "\n"), $digest->digest());
    }

    /**
     * With no id the digest is the SHA-256 of no bytes.
     *
     * @return void
     */
    public function testTheEmptySetDigestIsTheSha256OfNoBytes(): void
    {
        self::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', (new MembershipDigest)->digest());
    }

    /**
     * The same ids in another order digest differently, so the order of the
     * file is bound.
     *
     * @return void
     */
    public function testOrderMatters(): void
    {
        $forward  = new MembershipDigest;
        $backward = new MembershipDigest;

        $forward->add(self::FIRST);
        $forward->add(self::SECOND);
        $backward->add(self::SECOND);
        $backward->add(self::FIRST);

        self::assertNotSame($forward->digest(), $backward->digest());
    }

    /**
     * The digest is taken once and kept, so asking again gives the same digest
     * rather than the digest of nothing.
     *
     * @return void
     */
    public function testTheDigestIsKept(): void
    {
        $digest = new MembershipDigest;

        $digest->add(self::FIRST);

        $taken = $digest->digest();

        self::assertSame($taken, $digest->digest());
        self::assertSame(hash('sha256', self::FIRST . "\n"), $taken);
    }

    /**
     * An id added once the digest is taken is refused, since it could never be
     * part of it.
     *
     * @return void
     */
    public function testAnIdAfterTheDigestIsRefused(): void
    {
        $digest = new MembershipDigest;

        $digest->digest();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A membership digest takes no id once it has been taken.');

        $digest->add(self::FIRST);
    }
}
