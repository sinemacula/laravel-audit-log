<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;

/**
 * Unit tests for the exception reported beside every integrity failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityCheckFailedException::class)]
final class IntegrityCheckFailedExceptionTest extends TestCase
{
    /** @var string The id of the seal a test's finding was found at. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /**
     * The message names the command, each failing count, the finding, its id
     * and the head.
     *
     * @return void
     */
    public function testTheMessageIsPinned(): void
    {
        $event = new IntegrityCheckFailed(
            'verify',
            ['valid' => 9, 'pruned' => 8, 'incomplete' => 2, 'unverifiable' => 3, 'tampered' => 1],
            ['anchored' => 7, 'unanchored' => 4, 'unavailable' => 5, 'contradicted' => 6],
            'seal_digest',
            self::SEAL_ID,
            12,
            11,
            true,
        );

        $message = 'The audit log\'s integrity check failed (verify): 1 tampered, 2 incomplete, 3 unverifiable; 4 unanchored,'
            . ' 5 unavailable, 6 contradicted; first finding seal_digest at ' . self::SEAL_ID . '; head 12.';

        self::assertSame($message, IntegrityCheckFailedException::of($event)->getMessage());
        self::assertSame(0, IntegrityCheckFailedException::of($event)->getCode());
    }

    /**
     * A finding, id or head the event lacks is written `none`, and a missing
     * count reads zero.
     *
     * @return void
     */
    public function testAbsentPartsAreWrittenNone(): void
    {
        $event = new IntegrityCheckFailed('seal', [], ['unanchored' => 2], null, null, null, null, false);

        $message = 'The audit log\'s integrity check failed (seal): 0 tampered, 0 incomplete, 0 unverifiable; 2 unanchored,'
            . ' 0 unavailable, 0 contradicted; first finding none at none; head none.';

        self::assertSame($message, IntegrityCheckFailedException::of($event)->getMessage());

        $empty = new IntegrityCheckFailed('seal', [], [], null, null, null, null, false);

        $counts = ': 0 tampered, 0 incomplete, 0 unverifiable; 0 unanchored, 0 unavailable, 0 contradicted;';

        self::assertStringContainsString($counts, IntegrityCheckFailedException::of($empty)->getMessage());
    }

    /**
     * A head of zero is written as a number, not as absent.
     *
     * @return void
     */
    public function testAHeadOfZeroIsWrittenAsANumber(): void
    {
        $event = new IntegrityCheckFailed('verify', [], [], 'genesis', self::SEAL_ID, 0, null, true);

        self::assertStringEndsWith('first finding genesis at ' . self::SEAL_ID . '; head 0.', IntegrityCheckFailedException::of($event)->getMessage());
    }

    /**
     * A run that stopped names the command and the class of what stopped it,
     * and nothing else.
     *
     * @return void
     */
    public function testAStoppedRunNamesTheClass(): void
    {
        self::assertSame(
            'The audit log\'s verify run stopped with Illuminate\Database\QueryException; its integrity was not established.',
            IntegrityCheckFailedException::stopped('verify', 'Illuminate\Database\QueryException')->getMessage(),
        );
        self::assertSame(
            'The audit log\'s seal run stopped with RuntimeException; its integrity was not established.',
            IntegrityCheckFailedException::stopped('seal', \RuntimeException::class)->getMessage(),
        );
    }

    /**
     * The exception never carries another, whichever way it is built, so no
     * failure's message or bindings reach a report through it.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        $event = new IntegrityCheckFailed('verify', [], [], 'seal_digest', self::SEAL_ID, 1, null, true);

        self::assertNull(IntegrityCheckFailedException::of($event)->getPrevious());
        self::assertNull(IntegrityCheckFailedException::stopped('verify', \RuntimeException::class)->getPrevious());
    }

    /**
     * The exception is a final runtime exception.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, IntegrityCheckFailedException::stopped('seal', \RuntimeException::class));
        self::assertTrue((new \ReflectionClass(IntegrityCheckFailedException::class))->isFinal());
    }

    /**
     * Rows of `[first bad id]`: ids read from an altered table that are no
     * lower-case UUID, a line break or a control character among them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnnameableIds(): iterable
    {
        yield from [
            'a line break'       => [self::SEAL_ID . "\nforged log line"],
            'a control byte'     => [self::SEAL_ID . "\x1b[31m"],
            'an upper-case id'   => [strtoupper(self::SEAL_ID)],
            'one character more' => [self::SEAL_ID . '0'],
            'empty'              => [''],
        ];
    }

    /**
     * An id that is no lower-case UUID is written `none`, so text from an
     * altered table never reaches a log.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideUnnameableIds')]
    public function testAnIdThatIsNoUuidIsNeverNamed(string $id): void
    {
        $event   = new IntegrityCheckFailed('verify', ['tampered' => 1], [], 'member_hmac', $id, 2, null, true);
        $message = IntegrityCheckFailedException::of($event)->getMessage();

        self::assertStringContainsString('first finding member_hmac at none; head 2.', $message);
        self::assertStringNotContainsString("\n", $message);
    }
}
