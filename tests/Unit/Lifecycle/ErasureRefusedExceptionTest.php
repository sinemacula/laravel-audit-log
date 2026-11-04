<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;

/**
 * Unit tests for the exception an erasure is refused with: its refusal, its
 * reasons each once and sorted bytewise, the owner's fingerprint and its key, a
 * message that names the refusal and how many reasons it has and nothing of the
 * owner, a reason or a fingerprint, and no previous exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureRefusedException::class)]
final class ErasureRefusedExceptionTest extends TestCase
{
    /** @var string The owner's fingerprint. */
    private const string FINGERPRINT = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

    /**
     * The refusal, its reasons each once and sorted bytewise, and the owner's
     * fingerprint and its key are carried.
     *
     * @return void
     */
    public function testCarriesTheRefusalItsReasonsAndTheFingerprint(): void
    {
        $exception = ErasureRefusedException::of(ErasureRefusal::BLOCKED, ['unverified', 'held:b', 'held:a', 'held:b'], self::FINGERPRINT, 'k1');

        self::assertSame(ErasureRefusal::BLOCKED, $exception->refusal());
        self::assertSame(['held:a', 'held:b', 'unverified'], $exception->reasons());
        self::assertSame(self::FINGERPRINT, $exception->fingerprint());
        self::assertSame('k1', $exception->fingerprintKey());
    }

    /**
     * Rows of `[refusal, reasons, message]`: the message names the refusal and
     * how many distinct reasons it has, in the singular for one.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal, 1: list<string>, 2: string}>
     */
    public static function provideMessages(): iterable
    {
        yield from [
            'no reason'        => [ErasureRefusal::PENDING_DELIVERY, [], 'The erasure was refused (`pending_delivery`, 0 reasons); nothing was written.'],
            'one reason'       => [ErasureRefusal::UNSUPPORTED_ENCRYPTER, ['App\Vault'], 'The erasure was refused (`unsupported_encrypter`, 1 reason); nothing was written.'],
            'repeated reasons' => [ErasureRefusal::BLOCKED, ['held:a', 'held:a', 'unverified'], 'The erasure was refused (`blocked`, 2 reasons); nothing was written.'],
            'keys that fail'   => [ErasureRefusal::KEY_UNVERIFIABLE, ['01932b4e-0001'], 'The erasure was refused (`key_unverifiable`, 1 reason); nothing was written.'],
            'too many keys'    => [ErasureRefusal::TOO_MANY_KEYS, [], 'The erasure was refused (`too_many_keys`, 0 reasons); nothing was written.'],
        ];
    }

    /**
     * The message names the refusal and how many reasons it has, and never a
     * reason, the owner or the fingerprint.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal  $refusal
     * @param  list<string>  $reasons
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMessages')]
    public function testTheMessageNamesTheRefusalAndItsCount(ErasureRefusal $refusal, array $reasons, string $message): void
    {
        $exception = ErasureRefusedException::of($refusal, $reasons, self::FINGERPRINT, 'k1');

        self::assertSame($message, $exception->getMessage());
        self::assertStringNotContainsString(self::FINGERPRINT, $exception->getMessage());

        foreach ($reasons as $reason) {
            self::assertStringNotContainsString($reason, $exception->getMessage());
        }
    }

    /**
     * It carries no previous exception and no code, and is a runtime exception.
     *
     * @return void
     */
    public function testCarriesNoPreviousException(): void
    {
        $exception = ErasureRefusedException::of(ErasureRefusal::BLOCKED, ['unverified'], self::FINGERPRINT, 'k1');

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
