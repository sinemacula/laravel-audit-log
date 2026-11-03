<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for a record's attachment: sealing a manifest once under the
 * encrypter, the fields it refuses, the descriptor it answers to, and the
 * object a bundle carries it as.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Attachment::class)]
final class AttachmentTest extends TestCase
{
    /** @var string An artifact id as a manifest makes it. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000002';

    /** @var string The id of the entry an attachment belongs to. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A digest of the right shape. */
    private const string DIGEST = '0bee9fea9443d63a556a7fe8d19b18920d8aac7c234e48afc739a4df9380ed4d';

    /**
     * Sealing encrypts the manifest's canonical form, which the encrypter opens
     * again, and keeps its id, kind, count and digest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testSealingEncryptsTheCanonicalForm(): void
    {
        $manifest   = self::manifest();
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());

        self::assertSame($manifest->canonical, RecordFactory::encrypter()->decryptString($attachment->members));
        self::assertSame($manifest->id, $attachment->id);
        self::assertSame(Attachment::KIND_BULK, $attachment->kind);
        self::assertSame('bulk', $attachment->kind);
        self::assertSame(3, $attachment->memberCount);
        self::assertSame($manifest->digest, $attachment->digest);
    }

    /**
     * Sealing calls the encrypter once, with the canonical form as a string,
     * never serialised.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testSealingEncryptsOnceAsAString(): void
    {
        $manifest  = self::manifest();
        $encrypter = new class implements StringEncrypter {
            /** @var list<string> What the encrypter was given. */
            public array $given = [];

            /**
             * Record the plaintext and return a fixed ciphertext.
             *
             * @param  mixed  $value
             * @return string
             */
            #[\Override]
            public function encryptString(#[\SensitiveParameter] mixed $value): string
            {
                $this->given[] = is_string($value) ? $value : get_debug_type($value);

                return 'sealed';
            }

            /**
             * Never called.
             *
             * @param  mixed  $payload
             * @return string
             */
            #[\Override]
            public function decryptString(mixed $payload): string
            {
                return '';
            }
        };

        self::assertSame('sealed', Attachment::sealed($manifest, $encrypter)->members);
        self::assertSame([$manifest->canonical], $encrypter->given);
    }

    /**
     * An encrypter's failure is passed on, and no attachment is made.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnEncrypterFailureIsPassedOn(): void
    {
        $encrypter = new class implements StringEncrypter {
            /**
             * Fail to encrypt.
             *
             * @param  mixed  $value
             * @return string
             *
             * @throws \Illuminate\Contracts\Encryption\EncryptException
             */
            #[\Override]
            public function encryptString(#[\SensitiveParameter] mixed $value): string
            {
                throw new EncryptException('Could not encrypt the data.');
            }

            /**
             * Never called.
             *
             * @param  mixed  $payload
             * @return string
             */
            #[\Override]
            public function decryptString(mixed $payload): string
            {
                return '';
            }
        };

        $this->expectException(EncryptException::class);

        Attachment::sealed(self::manifest(), $encrypter);
    }

    /**
     * The ciphertext is not the plaintext and holds no member, and sealing the
     * same manifest twice gives two ciphertexts, so the members are sealed once
     * and carried, never sealed again.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheCiphertextIsNotThePlaintext(): void
    {
        $manifest = self::manifest();
        $first    = Attachment::sealed($manifest, RecordFactory::encrypter());
        $second   = Attachment::sealed($manifest, RecordFactory::encrypter());

        self::assertNotSame($manifest->canonical, $first->members);
        self::assertStringNotContainsString('Invoice', $first->members);
        self::assertStringNotContainsString('Invoice', base64_decode($first->members, true) ?: '');
        self::assertNotSame($first->members, $second->members);
    }

    /**
     * An attachment read from a bundle keeps every field as given.
     *
     * @return void
     */
    public function testAnEnvelopeIsReadBack(): void
    {
        $attachment = Attachment::fromEnvelope(self::fields());

        self::assertSame([self::ID, 'bulk', 3, self::DIGEST, 'ciphertext'], [
            $attachment->id, $attachment->kind, $attachment->memberCount, $attachment->digest, $attachment->members,
        ]);
        self::assertSame(self::fields(), $attachment->envelopeFor(self::ENTRY_ID));
    }

    /**
     * Rows of `[field, value, message]`: each field missing, of another type,
     * or malformed.
     *
     * @return iterable<string, array{0: string, 1: int|string|null, 2: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        yield from [
            'no id'                     => ['id', null, 'An attachment\'s `id` must be a string.'],
            'an integer id'             => ['id', 1, 'An attachment\'s `id` must be a string.'],
            'an upper-case id'          => ['id', strtoupper(self::ID), 'An attachment\'s `id` must be a lower-case UUID.'],
            'an id that is not a UUID'  => ['id', 'inv_0042', 'An attachment\'s `id` must be a lower-case UUID.'],
            'an id with a newline'      => ['id', self::ID . "\n", 'An attachment\'s `id` must be a lower-case UUID.'],
            'no kind'                   => ['kind', null, 'An attachment\'s `kind` must be a string.'],
            'another kind'              => ['kind', 'export', 'An attachment\'s `kind` must be `bulk`.'],
            'an upper-case kind'        => ['kind', 'BULK', 'An attachment\'s `kind` must be `bulk`.'],
            'no count'                  => ['member_count', null, 'An attachment\'s `member_count` must be an integer.'],
            'a string count'            => ['member_count', '3', 'An attachment\'s `member_count` must be an integer.'],
            'a count of nought'         => ['member_count', 0, 'An attachment\'s `member_count` must be at least 1.'],
            'a negative count'          => ['member_count', -1, 'An attachment\'s `member_count` must be at least 1.'],
            'no digest'                 => ['digest', null, 'An attachment\'s `digest` must be a string.'],
            'an upper-case digest'      => ['digest', strtoupper(self::DIGEST), 'An attachment\'s `digest` must be a lower-case hex SHA-256.'],
            'a short digest'            => ['digest', substr(self::DIGEST, 1), 'An attachment\'s `digest` must be a lower-case hex SHA-256.'],
            'a digest with a newline'   => ['digest', self::DIGEST . "\n", 'An attachment\'s `digest` must be a lower-case hex SHA-256.'],
            'no members'                => ['members', null, 'An attachment\'s `members` must be a string.'],
            'members that are a number' => ['members', 1, 'An attachment\'s `members` must be a string.'],
            'empty members'             => ['members', '', 'An attachment\'s `members` must be a ciphertext.'],
        ];
    }

    /**
     * A malformed field is refused, naming the field and what it must be, never
     * its value; a missing field is read as `null`.
     *
     * @param  string  $field
     * @param  int|string|null  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesAMalformedField(string $field, int|string|null $value, string $message): void
    {
        $fields = self::fields();

        if ($value === null) {
            unset($fields[$field]);
        } else {
            $fields[$field] = $value;
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Attachment::fromEnvelope($fields);
    }

    /**
     * The smallest count, one member, is kept.
     *
     * @return void
     */
    public function testOneMemberIsEnough(): void
    {
        self::assertSame(1, Attachment::fromEnvelope(['member_count' => 1] + self::fields())->memberCount);
    }

    /**
     * An attachment describes exactly its own descriptor, in any key order:
     * another id, digest or count, a value of another type, a key missing or a
     * key added is another descriptor.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesOnlyItsOwnDescriptor(): void
    {
        $manifest   = self::manifest();
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());
        $descriptor = $manifest->descriptor();

        self::assertTrue($attachment->describes($descriptor));
        self::assertTrue($attachment->describes(['count' => 3, 'digest' => $manifest->digest, 'artifact_id' => $manifest->id]));

        $others = [
            'another id'       => ['artifact_id' => self::ID]       + $descriptor,
            'another digest'   => ['digest' => str_repeat('a', 64)] + $descriptor,
            'another count'    => ['count' => 4]                    + $descriptor,
            'a string count'   => ['count' => '3']                  + $descriptor,
            'no id'            => array_diff_key($descriptor, ['artifact_id' => true]),
            'no digest'        => array_diff_key($descriptor, ['digest' => true]),
            'no count'         => array_diff_key($descriptor, ['count' => true]),
            'a key added'      => $descriptor + ['kind' => 'bulk'],
            'nothing'          => [],
            'another manifest' => self::manifest()->descriptor(),
            'the id as a list' => [$manifest->id, $manifest->digest, 3],
        ];

        foreach ($others as $label => $other) {
            self::assertFalse($attachment->describes($other), $label);
        }
    }

    /**
     * The envelope names the entry it belongs to beside every field, in the
     * order a bundle carries them.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheEnvelopeNamesItsEntry(): void
    {
        $manifest   = self::manifest();
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());

        self::assertSame([
            'id'           => $manifest->id,
            'entry_id'     => self::ENTRY_ID,
            'kind'         => 'bulk',
            'member_count' => 3,
            'digest'       => $manifest->digest,
            'members'      => $attachment->members,
        ], $attachment->envelopeFor(self::ENTRY_ID));
        self::assertEquals($attachment, Attachment::fromEnvelope($attachment->envelopeFor(self::ENTRY_ID)));
    }

    /**
     * The members, the manifest sealed and the fields read are marked
     * sensitive.
     *
     * @return void
     */
    public function testTheMembersAreSensitive(): void
    {
        $parameters = [
            (new \ReflectionMethod(Attachment::class, '__construct'))->getParameters()[4],
            (new \ReflectionMethod(Attachment::class, 'sealed'))->getParameters()[0],
            (new \ReflectionMethod(Attachment::class, 'fromEnvelope'))->getParameters()[0],
        ];

        foreach ($parameters as $parameter) {
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), $parameter->getName());
        }
    }

    /**
     * A manifest of the golden members.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \JsonException
     */
    private static function manifest(): Manifest
    {
        $type = 'App\Models\Invoice';

        return Manifest::of([Reference::of($type, '2'), Reference::of($type, '1'), Reference::of($type, '10')], 10, 65536);
    }

    /**
     * A bundle's attachment object of the right shape.
     *
     * @return array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string}
     */
    private static function fields(): array
    {
        return [
            'id'           => self::ID,
            'entry_id'     => self::ENTRY_ID,
            'kind'         => 'bulk',
            'member_count' => 3,
            'digest'       => self::DIGEST,
            'members'      => 'ciphertext',
        ];
    }
}
