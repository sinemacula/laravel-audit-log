<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;

/**
 * Unit tests for the exception that refuses an envelope: the failure it keeps,
 * the id it keeps only when it is a lower-case UUID, the fixed message of each
 * failure that holds nothing of the envelope, and that it has no previous
 * exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnvelopeRejectedException::class)]
final class EnvelopeRejectedExceptionTest extends TestCase
{
    /** @var string A record id in the form every engine stores. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * The exception keeps the failure it is given, and is an unexpected value:
     * the envelope came back wrong.
     *
     * @return void
     */
    public function testKeepsTheFailure(): void
    {
        $exception = new EnvelopeRejectedException(EnvelopeFailure::UNKNOWN_KEY, self::ID);

        self::assertSame(EnvelopeFailure::UNKNOWN_KEY, $exception->failure);
        self::assertInstanceOf(\UnexpectedValueException::class, $exception);
        self::assertSame(0, $exception->getCode());
    }

    /**
     * Rows of `[id as read, id kept]`: a lower-case UUID is kept, and anything
     * else, which may be hostile bytes, is not.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideIds(): iterable
    {
        yield from [
            'a lower-case UUID'       => [self::ID, self::ID],
            'none'                    => [null, null],
            'an upper-case UUID'      => [strtoupper(self::ID), null],
            'a UUID and a line feed'  => [self::ID . "\n", null],
            'a line feed and a UUID'  => ["\n" . self::ID, null],
            'a UUID without hyphens'  => [str_replace('-', '', self::ID), null],
            'a terminal escape'       => ["\e[31m" . self::ID, null],
            'an empty string'         => ['', null],
            'one character too short' => [substr(self::ID, 0, -1), null],
            'one character too long'  => [self::ID . '0', null],
            'a letter beyond f'       => [substr(self::ID, 0, -1) . 'g', null],
        ];
    }

    /**
     * The id is kept only when it is a lower-case UUID, the one form a record
     * id takes, so hostile bytes in an envelope never reach a console.
     *
     * @param  ?string  $id
     * @param  ?string  $kept
     * @return void
     */
    #[DataProvider('provideIds')]
    public function testKeepsAnIdOnlyWhenItIsAUuid(?string $id, ?string $kept): void
    {
        self::assertSame($kept, (new EnvelopeRejectedException(EnvelopeFailure::MALFORMED, $id))->id);
    }

    /**
     * Rows of `[failure, message]`: each failure and its fixed message.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure, 1: string}>
     */
    public static function provideMessages(): iterable
    {
        yield from [
            'a signature mismatch'   => [EnvelopeFailure::SIGNATURE_MISMATCH, 'The audit envelope\'s signature does not match its content.'],
            'an unknown key'         => [EnvelopeFailure::UNKNOWN_KEY, 'The audit envelope names an integrity key the key ring does not hold, so it cannot be verified.'],
            'an unsupported version' => [EnvelopeFailure::UNSUPPORTED_VERSION, 'The audit envelope is in a record or integrity version this release does not read.'],
            'a malformed envelope'   => [EnvelopeFailure::MALFORMED, 'The audit envelope is not a well-formed audit record.'],
            'a truncated envelope'   => [EnvelopeFailure::TRUNCATED, 'The audit envelope is truncated.'],
            'an unsigned envelope'   => [EnvelopeFailure::UNSIGNED, 'The audit envelope is unsigned, so it cannot be verified.'],
            'an id mismatch'         => [EnvelopeFailure::ID_MISMATCH, 'The audit envelope\'s id is not the id it was kept under.'],
            'an oversize envelope'   => [EnvelopeFailure::OVERSIZE, 'The audit envelope is larger than any audit record can be.'],
        ];
    }

    /**
     * Each failure has its own fixed message, which names neither the id nor
     * anything else the envelope held, kept or not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure  $failure
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMessages')]
    public function testTheMessageHoldsNoContent(EnvelopeFailure $failure, string $message): void
    {
        $kept    = new EnvelopeRejectedException($failure, self::ID);
        $refused = new EnvelopeRejectedException($failure, "secret\n" . self::ID);
        $none    = new EnvelopeRejectedException($failure);

        self::assertSame($message, $kept->getMessage());
        self::assertSame($message, $refused->getMessage());
        self::assertSame($message, $none->getMessage());
        self::assertStringNotContainsString(self::ID, $kept->getMessage());
    }

    /**
     * Every failure's message is distinct, so a log line alone says which it
     * was.
     *
     * @return void
     */
    public function testEachFailureHasItsOwnMessage(): void
    {
        $messages = array_map(static fn (EnvelopeFailure $failure): string => (new EnvelopeRejectedException($failure))->getMessage(), EnvelopeFailure::cases());

        self::assertCount(count(EnvelopeFailure::cases()), array_unique($messages));
    }

    /**
     * The exception has no previous exception, whatever the failure, so the
     * parser's or the signer's exception, and what it holds, never reaches a
     * handler.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        foreach (EnvelopeFailure::cases() as $failure) {
            self::assertNull((new EnvelopeRejectedException($failure, self::ID))->getPrevious(), $failure->value);
        }
    }

    /**
     * The exception is final, so no subclass can add a previous exception or a
     * message of its own.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        self::assertTrue((new \ReflectionClass(EnvelopeRejectedException::class))->isFinal());
    }
}
