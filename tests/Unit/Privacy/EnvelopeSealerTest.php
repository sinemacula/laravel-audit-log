<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;
use Tests\Fixtures\Privacy\MalformedFieldEncrypter;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;

/**
 * Unit tests for the envelope sealer: the envelopes it accepts and the order it
 * returns them in, the failures it contains, and that a failure reaches the
 * reporter once, holding nothing of the plaintext.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnvelopeSealer::class)]
#[CoversClass(FieldEncryptionFailedException::class)]
final class EnvelopeSealerTest extends TestCase
{
    /** @var string The plaintext sealed; short enough that a string trace would show it whole. */
    private const string PLAINTEXT = 's3cr3t';

    /**
     * An envelope comes back as `v`, `k` and `c` whatever order it was returned
     * in, so what is stored and signed never depends on the encrypter's order.
     *
     * @return void
     */
    public function testAValidEnvelopeComesBackInItsFixedOrder(): void
    {
        $handler = new RecordingExceptionHandler;
        $sealer  = new EnvelopeSealer(new MalformedFieldEncrypter(['c' => 'ciphertext', 'v' => 1, 'k' => 'key_1']), $handler);

        self::assertSame(['v' => 1, 'k' => 'key_1', 'c' => 'ciphertext'], $sealer->seal(self::owner(), self::PLAINTEXT));
        self::assertSame([], $handler->reports());
    }

    /**
     * The encrypter is given the owner and the plaintext exactly as they came,
     * and what it returns is what comes back.
     *
     * @return void
     */
    public function testTheEncrypterIsGivenTheOwnerAndThePlaintext(): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $owner     = self::owner();

        $envelope = (new EnvelopeSealer($encrypter, new RecordingExceptionHandler))->seal($owner, self::PLAINTEXT);

        self::assertSame([[$owner, self::PLAINTEXT]], $encrypter->calls());
        self::assertSame(['v' => 1, 'k' => 'key_42', 'c' => base64_encode(self::PLAINTEXT)], $envelope);
    }

    /**
     * Rows of `[version]`: the first and the last version an envelope may have.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideVersionsAtTheirLimits(): iterable
    {
        yield from [
            'the least'        => [1],
            'the safe integer' => [ValueNormaliser::MAX_SAFE_INTEGER],
        ];
    }

    /**
     * A version at either end of its range is accepted.
     *
     * @param  int  $version
     * @return void
     */
    #[DataProvider('provideVersionsAtTheirLimits')]
    public function testAVersionAtItsLimitIsAccepted(int $version): void
    {
        $handler = new RecordingExceptionHandler;
        $sealer  = new EnvelopeSealer(new MalformedFieldEncrypter(['v' => $version, 'k' => 'key_1', 'c' => 'ciphertext']), $handler);

        self::assertSame(['v' => $version, 'k' => 'key_1', 'c' => 'ciphertext'], $sealer->seal(self::owner(), self::PLAINTEXT));
        self::assertSame([], $handler->reports());
    }

    /**
     * An owner with no key is an answer, not a failure: there is no envelope
     * and nothing to report.
     *
     * @return void
     */
    public function testNoKeyIsNotAFailureAndReportsNothing(): void
    {
        $handler = new RecordingExceptionHandler;

        self::assertNull((new EnvelopeSealer(new NoFieldEncrypter, $handler))->seal(self::owner(), self::PLAINTEXT));
        self::assertSame([], $handler->reports());
    }

    /**
     * Rows of `[envelope]`: everything that is not exactly a valid `v`, `k` and
     * `c`.
     *
     * @return iterable<string, array{0: array<array-key, array<array-key, string>|bool|float|int|string|null>}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        yield from [
            'empty'                      => [[]],
            'no v'                       => [['k' => 'key_1', 'c' => 'ciphertext']],
            'no k'                       => [['v' => 1, 'c' => 'ciphertext']],
            'no c'                       => [['v' => 1, 'k' => 'key_1']],
            'an extra key'               => [['v' => 1, 'k' => 'key_1', 'c' => 'ciphertext', 'x' => 'extra']],
            'three parts, one misnamed'  => [['v' => 1, 'k' => 'key_1', 'x' => 'ciphertext']],
            'a list of three'            => [[1, 'key_1', 'ciphertext']],
            'v a string'                 => [['v' => '1', 'k' => 'key_1', 'c' => 'ciphertext']],
            'v a float'                  => [['v' => 1.0, 'k' => 'key_1', 'c' => 'ciphertext']],
            'v true'                     => [['v' => true, 'k' => 'key_1', 'c' => 'ciphertext']],
            'v null'                     => [['v' => null, 'k' => 'key_1', 'c' => 'ciphertext']],
            'v 0'                        => [['v' => 0, 'k' => 'key_1', 'c' => 'ciphertext']],
            'v negative'                 => [['v' => -1, 'k' => 'key_1', 'c' => 'ciphertext']],
            'v above the safe integer'   => [['v' => ValueNormaliser::MAX_SAFE_INTEGER + 1, 'k' => 'key_1', 'c' => 'ciphertext']],
            'k empty'                    => [['v' => 1, 'k' => '', 'c' => 'ciphertext']],
            'c empty'                    => [['v' => 1, 'k' => 'key_1', 'c' => '']],
            'k an integer'               => [['v' => 1, 'k' => 1, 'c' => 'ciphertext']],
            'k null'                     => [['v' => 1, 'k' => null, 'c' => 'ciphertext']],
            'c an array'                 => [['v' => 1, 'k' => 'key_1', 'c' => ['ciphertext']]],
            'c null'                     => [['v' => 1, 'k' => 'key_1', 'c' => null]],
            'k invalid UTF-8'            => [['v' => 1, 'k' => "key\xFF", 'c' => 'ciphertext']],
            'c invalid UTF-8'            => [['v' => 1, 'k' => 'key_1', 'c' => "cipher\xFF"]],
            'k with a control character' => [['v' => 1, 'k' => "key\n1", 'c' => 'ciphertext']],
            'c with a control character' => [['v' => 1, 'k' => 'key_1', 'c' => "cipher\x00text"]],
        ];
    }

    /**
     * Each malformed envelope gives no envelope and is reported, once, as a
     * failure.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $envelope
     * @return void
     */
    #[DataProvider('provideMalformedEnvelopes')]
    public function testAMalformedEnvelopeIsAFailure(array $envelope): void
    {
        $handler = new RecordingExceptionHandler;
        $sealer  = new EnvelopeSealer(new MalformedFieldEncrypter($envelope), $handler);

        self::assertNull($sealer->seal(self::owner(), self::PLAINTEXT));
        self::assertCount(1, $handler->reports());
        self::assertInstanceOf(FieldEncryptionFailedException::class, $handler->reports()[0]);
    }

    /**
     * An exception from the encrypter stops at the sealer: the caller gets no
     * envelope and carries on.
     *
     * @return void
     */
    public function testAThrowingEncrypterIsContained(): void
    {
        $handler = new RecordingExceptionHandler;

        self::assertNull((new EnvelopeSealer(new ThrowingFieldEncrypter, $handler))->seal(self::owner(), self::PLAINTEXT));
        self::assertCount(1, $handler->reports());
    }

    /**
     * An `\Error` is contained as well, since a bug in an encrypter is no more
     * reason to lose the record than a refusal is.
     *
     * @return void
     */
    public function testAnErrorIsContainedToo(): void
    {
        $handler = new RecordingExceptionHandler;

        self::assertNull((new EnvelopeSealer(new ThrowingFieldEncrypter(throwsAnError: true), $handler))->seal(self::owner(), self::PLAINTEXT));
        self::assertCount(1, $handler->reports());
    }

    /**
     * Rows of `[encrypter]`: the ways an encrypter can fail, each with the
     * plaintext within its reach.
     *
     * @return iterable<string, array{0: \Tests\Fixtures\Privacy\MalformedFieldEncrypter|\Tests\Fixtures\Privacy\ThrowingFieldEncrypter}>
     */
    public static function provideFailingEncrypters(): iterable
    {
        yield from [
            'an exception holding the plaintext' => [new ThrowingFieldEncrypter],
            'an error holding the plaintext'     => [new ThrowingFieldEncrypter(throwsAnError: true)],
            'an envelope holding the plaintext'  => [new MalformedFieldEncrypter(['v' => 1, 'k' => self::PLAINTEXT])],
        ];
    }

    /**
     * What is reported is the package's own exception, naming only the
     * encrypter's class, with no previous exception, and with frames that keep
     * the plaintext out of its trace even with arguments recorded.
     *
     * @param  \Tests\Fixtures\Privacy\MalformedFieldEncrypter|\Tests\Fixtures\Privacy\ThrowingFieldEncrypter  $encrypter
     * @return void
     */
    #[DataProvider('provideFailingEncrypters')]
    public function testAFailureReportsThePayloadFreeExceptionWithNoPrevious(MalformedFieldEncrypter|ThrowingFieldEncrypter $encrypter): void
    {
        $handler = new RecordingExceptionHandler;
        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            (new EnvelopeSealer($encrypter, $handler))->seal(self::owner(), self::PLAINTEXT);
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }

        $report  = $handler->reports()[0];
        $classes = [EnvelopeSealer::class, FieldEncryptionFailedException::class];
        $frames  = array_values(array_filter($report->getTrace(), static fn (array $frame): bool => in_array($frame['class'] ?? null, $classes, true)));

        self::assertSame(FieldEncryptionFailedException::class, $report::class);
        self::assertSame('The field encrypter ' . $encrypter::class . ' failed, so the value was dropped.', $report->getMessage());
        self::assertNull($report->getPrevious());
        self::assertStringNotContainsString(self::PLAINTEXT, $report->getTraceAsString());
        self::assertNotSame([], $frames);
        self::assertStringNotContainsString(self::PLAINTEXT, print_r($frames, true));
        self::assertStringNotContainsString(self::PLAINTEXT, (string) $report);
    }

    /**
     * A failure reaches the reporter once, however many values the capture goes
     * on to seal.
     *
     * @return void
     */
    public function testAFailureIsReportedOncePerCapture(): void
    {
        $handler = new RecordingExceptionHandler;
        $sealer  = new EnvelopeSealer(new MalformedFieldEncrypter([]), $handler);

        foreach (range(1, 3) as $attempt) {
            self::assertNull($sealer->seal(self::owner(), self::PLAINTEXT), "Seal {$attempt} gave an envelope.");
        }

        self::assertCount(1, $handler->reports());
    }

    /**
     * A throwing encrypter is asked once, so a wildcard over thousands of
     * elements does not keep sending plaintext to something broken.
     *
     * @return void
     */
    public function testAfterAFailureTheEncrypterIsNotCalledAgain(): void
    {
        $encrypter = new ThrowingFieldEncrypter;
        $sealer    = new EnvelopeSealer($encrypter, new RecordingExceptionHandler);

        $sealer->seal(self::owner(), self::PLAINTEXT);
        $sealer->seal(self::owner(), self::PLAINTEXT);

        self::assertSame(1, $encrypter->calls());
    }

    /**
     * A malformed envelope stops further calls as a thrown exception does,
     * though the first call returned rather than threw.
     *
     * @return void
     */
    public function testAfterAMalformedEnvelopeTheEncrypterIsNotCalledAgain(): void
    {
        $encrypter = new MalformedFieldEncrypter([]);
        $sealer    = new EnvelopeSealer($encrypter, new RecordingExceptionHandler);

        $sealer->seal(self::owner(), self::PLAINTEXT);
        $sealer->seal(self::owner(), self::PLAINTEXT);

        self::assertSame(1, $encrypter->calls());
    }

    /**
     * An owner with no key says nothing of the next owner, so each is asked.
     *
     * @return void
     */
    public function testNoKeyDoesNotStopLaterCalls(): void
    {
        $encrypter = new class implements FieldEncrypter {
            /**
             * An envelope for the owner `42` alone.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
             * @param  string  $plaintext
             * @return ?array{v: int, k: string, c: string}
             */
            #[\Override]
            public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext): ?array
            {
                return $owner->id === '42' ? ['v' => 1, 'k' => 'key_42', 'c' => 'ciphertext'] : null;
            }
        };

        $handler = new RecordingExceptionHandler;
        $sealer  = new EnvelopeSealer($encrypter, $handler);

        self::assertNull($sealer->seal(Reference::of('user', 7), self::PLAINTEXT));
        self::assertSame(['v' => 1, 'k' => 'key_42', 'c' => 'ciphertext'], $sealer->seal(self::owner(), self::PLAINTEXT));
        self::assertSame([], $handler->reports());
    }

    /**
     * A valid envelope does not stop later calls either.
     *
     * @return void
     */
    public function testAValidEnvelopeDoesNotStopLaterCalls(): void
    {
        $encrypter = new RecordingFieldEncrypter;
        $sealer    = new EnvelopeSealer($encrypter, new RecordingExceptionHandler);

        $sealer->seal(self::owner(), 'one');
        $sealer->seal(self::owner(), 'two');

        self::assertCount(2, $encrypter->calls());
    }

    /**
     * Rows of `[encrypter]`: a failure by throwing and by returning, each of
     * which must survive a reporter that fails too.
     *
     * @return iterable<string, array{0: \Tests\Fixtures\Privacy\MalformedFieldEncrypter|\Tests\Fixtures\Privacy\ThrowingFieldEncrypter}>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'a throw'            => [new ThrowingFieldEncrypter],
            'a malformed return' => [new MalformedFieldEncrypter([])],
        ];
    }

    /**
     * A reporter that throws changes nothing: the caller still gets `null`, the
     * reporter was tried once, and the encrypter stays stopped.
     *
     * @param  \Tests\Fixtures\Privacy\MalformedFieldEncrypter|\Tests\Fixtures\Privacy\ThrowingFieldEncrypter  $encrypter
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testAFailingReporterIsIgnored(MalformedFieldEncrypter|ThrowingFieldEncrypter $encrypter): void
    {
        $handler = new RecordingExceptionHandler(throwsOnReport: true);
        $sealer  = new EnvelopeSealer($encrypter, $handler);

        self::assertNull($sealer->seal(self::owner(), self::PLAINTEXT));
        self::assertNull($sealer->seal(self::owner(), self::PLAINTEXT));
        self::assertCount(1, $handler->reports());
        self::assertSame(1, $encrypter->calls());
    }

    /**
     * The plaintext is marked sensitive, and the trace of a failure shows it:
     * the frame of `seal()` holds the marker in place of the value.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testThePlaintextParameterIsSensitive(): void
    {
        $parameter = new \ReflectionParameter([EnvelopeSealer::class, 'seal'], 'plaintext');

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));

        $handler = new RecordingExceptionHandler;
        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            (new EnvelopeSealer(new ThrowingFieldEncrypter, $handler))->seal(self::owner(), self::PLAINTEXT);
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }

        $seal = array_values(array_filter($handler->reports()[0]->getTrace(), static fn (array $frame): bool => $frame['function'] === 'seal'));

        self::assertCount(1, $seal);
        self::assertInstanceOf(\SensitiveParameterValue::class, ($seal[0]['args'] ?? [])[1] ?? null);
    }

    /**
     * The owner every test seals under.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('user', 42);
    }
}
