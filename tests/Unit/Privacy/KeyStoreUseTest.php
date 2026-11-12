<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\KeyStoreUse;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;

/**
 * Unit tests for whether the package's key store is in use, judged by the
 * encrypter's exact class, and how an encrypter is described.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyStoreUse::class)]
final class KeyStoreUseTest extends TestCase
{
    /**
     * The package's own encrypter and the one that never encrypts keep the key
     * store in use, and each is described by its class.
     *
     * @return void
     */
    public function testThePackagesEncryptersUseTheKeyStore(): void
    {
        $subjectKeys = (new \ReflectionClass(SubjectKeyEncrypter::class))->newInstanceWithoutConstructor();

        self::assertTrue(KeyStoreUse::covers($subjectKeys));
        self::assertTrue(KeyStoreUse::covers(new NoFieldEncrypter));
        self::assertSame(SubjectKeyEncrypter::class, KeyStoreUse::describe($subjectKeys));
        self::assertSame(NoFieldEncrypter::class, KeyStoreUse::describe(new NoFieldEncrypter));
    }

    /**
     * An application's own encrypter keeps its keys outside the package, so the
     * key store is not in use; it is described by its class.
     *
     * @return void
     */
    public function testACustomEncrypterDoesNot(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        self::assertFalse(KeyStoreUse::covers($encrypter));
        self::assertSame(RecordingFieldEncrypter::class, KeyStoreUse::describe($encrypter));
    }

    /**
     * A decorator of the package's encrypter does not count; anonymous, it is
     * described by its contract, never a name holding a file path.
     *
     * @return void
     */
    public function testADecoratorOfThePackagesEncrypterDoesNot(): void
    {
        $inner = (new \ReflectionClass(SubjectKeyEncrypter::class))->newInstanceWithoutConstructor();

        $decorator = new readonly class ($inner) implements FieldEncrypter {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $inner
             */
            public function __construct(

                /** The encrypter decorated. */
                private FieldEncrypter $inner,
            ) {}

            /**
             * The inner encrypter's envelope.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
             * @param  string  $plaintext
             * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
             * @return ?array{v: int, k: string, c: string}
             *
             * @throws \Throwable
             */
            #[\Override]
            public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): ?array
            {
                return $this->inner->encrypt($owner, $plaintext, $context);
            }
        };

        self::assertFalse(KeyStoreUse::covers($decorator));
        self::assertSame(FieldEncrypter::class . '@anonymous', KeyStoreUse::describe($decorator));
    }

    /**
     * `KeyStoreUse` cannot be instantiated: its constructor is private, and is
     * invoked here by reflection so the line is covered.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(KeyStoreUse::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(KeyStoreUse::class, $instance);
    }
}
