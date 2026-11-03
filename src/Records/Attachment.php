<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Contracts\Encryption\StringEncrypter;

/**
 * An artifact that travels with its record: a bulk operation's manifest,
 * described by its id, kind, member count and digest, with its members sealed
 * under the application's encrypter.
 *
 * The members are encrypted once, when the record is captured, and the same
 * ciphertext is carried by every retry, drain and replay, so a duplicate is
 * told by its description, never by its bytes. An attachment is not signed: it
 * is bound to its record by the descriptor the record signs at
 * `properties._audit.manifest`, which names its id, digest and count.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Attachment
{
    /** @var string The kind of a bulk operation's manifest, the only kind there is. */
    public const string KIND_BULK = Manifest::KIND;

    /** @var string A UUID as every engine returns it. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string SHA-256 as lower-case hex. */
    private const string DIGEST_PATTERN = '/\A[0-9a-f]{64}\z/';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $kind
     * @param  int  $memberCount
     * @param  string  $digest
     * @param  string  $members
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The artifact's id: a lower-case UUID. */
        public string $id,

        /** What kind of artifact it is: `bulk`. */
        public string $kind,

        /** How many members it holds, at least one. */
        public int $memberCount,

        /** Lower-case hex SHA-256 of the members' canonical form. */
        public string $digest,

        /** The members' canonical form, encrypted under the application's encrypter. */
        #[\SensitiveParameter]
        public string $members,
    ) {
        if (preg_match(self::UUID_PATTERN, $id) !== 1) {
            throw self::malformed('id', 'a lower-case UUID');
        }

        if ($kind !== self::KIND_BULK) {
            throw self::malformed('kind', '`' . self::KIND_BULK . '`');
        }

        if ($memberCount < 1) {
            throw self::malformed('member_count', 'at least 1');
        }

        if (preg_match(self::DIGEST_PATTERN, $digest) !== 1) {
            throw self::malformed('digest', 'a lower-case hex SHA-256');
        }

        if ($members === '') {
            throw self::malformed('members', 'a ciphertext');
        }
    }

    /**
     * The manifest sealed: its canonical form encrypted once, beside its id,
     * kind, count and digest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @param  \Illuminate\Contracts\Encryption\StringEncrypter  $encrypter
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     *
     * @internal
     */
    public static function sealed(#[\SensitiveParameter] Manifest $manifest, StringEncrypter $encrypter): self
    {
        return new self($manifest->id, Manifest::KIND, $manifest->count, $manifest->digest, $encrypter->encryptString($manifest->canonical));
    }

    /**
     * The attachment a bundle's `attachment` object holds, each field of its
     * type and checked as any other; its `entry_id` is the codec's to check.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function fromEnvelope(#[\SensitiveParameter] array $fields): self
    {
        $memberCount = $fields['member_count'] ?? null;

        return new self(
            self::stringOf($fields, 'id'),
            self::stringOf($fields, 'kind'),
            is_int($memberCount) ? $memberCount : throw self::malformed('member_count', 'an integer'),
            self::stringOf($fields, 'digest'),
            self::stringOf($fields, 'members'),
        );
    }

    /**
     * Whether the descriptor is exactly this attachment's: its artifact id,
     * digest and count, and nothing else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return bool
     */
    public function describes(array $descriptor): bool
    {
        return count($descriptor)                   === 3
            && ($descriptor['artifact_id'] ?? null) === $this->id
            && ($descriptor['digest'] ?? null)      === $this->digest
            && ($descriptor['count'] ?? null)       === $this->memberCount;
    }

    /**
     * The attachment as a bundle carries it, naming the entry it belongs to.
     *
     * @param  string  $entryId
     * @return array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string}
     */
    public function envelopeFor(string $entryId): array
    {
        return [
            'id'           => $this->id,
            'entry_id'     => $entryId,
            'kind'         => $this->kind,
            'member_count' => $this->memberCount,
            'digest'       => $this->digest,
            'members'      => $this->members,
        ];
    }

    /**
     * The bundle's field, which must be a string; a missing field is not.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  'digest'|'id'|'kind'|'members'  $field
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function stringOf(#[\SensitiveParameter] array $fields, string $field): string
    {
        $value = $fields[$field] ?? null;

        return is_string($value) ? $value : throw self::malformed($field, 'a string');
    }

    /**
     * The refusal of a malformed field, naming the field and what it must be,
     * never its value.
     *
     * @param  string  $field
     * @param  string  $what
     * @return \InvalidArgumentException
     */
    private static function malformed(string $field, string $what): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('An attachment\'s `%s` must be %s.', $field, $what));
    }
}
