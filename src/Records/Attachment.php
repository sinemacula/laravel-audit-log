<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Contracts\Encryption\StringEncrypter;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;

/**
 * An artifact that travels with its record, of any kind: a bulk operation's
 * subjects, a disclosure's evidence or an export's manifest, described by its
 * id, kind, member count and digest, with its canonical form sealed under the
 * application's encrypter. A bulk operation counts at least one member; a
 * disclosure or an export may count none.
 *
 * The members are encrypted once, when the record is captured, and the same
 * ciphertext is carried by every retry, drain and replay, so a duplicate is
 * told by its description, never by its bytes. An attachment is not signed: it
 * is bound to its record by the descriptor the record signs at
 * `properties._audit.manifest`, which names exactly its id, kind, digest and
 * count.
 *
 * An attachment described from a stored entry's descriptor alone carries no
 * members: it keeps a record rebuilt for reading bound to its descriptor, and
 * is never stored, queued or spilled, since it has nothing to store.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Attachment
{
    /** @var string A UUID as every engine returns it. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string SHA-256 as lower-case hex. */
    private const string DIGEST_PATTERN = '/\A[0-9a-f]{64}\z/';

    /** @var list<string> The keys of a descriptor, sorted: exactly these and nothing else. */
    private const array DESCRIPTOR_KEYS = ['artifact_id', 'count', 'digest', 'kind'];

    /** @var string The refusal of a descriptor that is not exactly its four keys, each of its type. */
    private const string DESCRIPTOR_MESSAGE = 'A manifest descriptor is exactly a string `artifact_id`, `kind` and `digest` and an integer `count`.';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $kind
     * @param  int  $memberCount
     * @param  string  $digest
     * @param  ?string  $members
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The artifact's id: a lower-case UUID. */
        public string $id,

        /** What kind of artifact it is: `bulk`, `disclosure` or `export`. */
        public string $kind,

        /** How many members it holds: at least one for `bulk`, and never fewer than none. */
        public int $memberCount,

        /** Lower-case hex SHA-256 of the members' canonical form. */
        public string $digest,

        /** The members' canonical form, encrypted under the application's encrypter; `null` only when described from an entry. */
        #[\SensitiveParameter]
        public ?string $members,
    ) {
        if (preg_match(self::UUID_PATTERN, $id) !== 1) {
            throw self::malformed('id', 'a lower-case UUID');
        }

        $artifactKind = ArtifactKind::tryFrom($kind) ?? throw self::malformed('kind', '`bulk`, `disclosure` or `export`');

        if ($memberCount < ($artifactKind->allowsEmpty() ? 0 : 1)) {
            throw self::malformed('member_count', $artifactKind->allowsEmpty() ? 'at least 0' : 'at least 1');
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
        return new self($manifest->id, $manifest->kind->value, $manifest->count, $manifest->digest, $encrypter->encryptString($manifest->canonical));
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
     * The attachment a stored entry's signed descriptor describes, for a record
     * rebuilt to be read: its id, kind, count and digest, and no members, so it
     * is never stored or encoded. A descriptor that is not exactly an artifact
     * id, a kind, a digest and a count, each well formed, is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function described(array $descriptor): self
    {
        $keys = array_keys($descriptor);

        sort($keys);

        if ($keys !== self::DESCRIPTOR_KEYS) {
            throw new \InvalidArgumentException(self::DESCRIPTOR_MESSAGE);
        }

        ['artifact_id' => $id, 'kind' => $kind, 'digest' => $digest, 'count' => $count] = $descriptor;

        if (!is_string($id) || !is_string($kind) || !is_string($digest) || !is_int($count)) {
            throw new \InvalidArgumentException(self::DESCRIPTOR_MESSAGE);
        }

        return new self($id, $kind, $count, $digest, null);
    }

    /**
     * Whether the descriptor is exactly this attachment's: its artifact id,
     * kind, digest and count, and nothing else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return bool
     */
    public function describes(array $descriptor): bool
    {
        ksort($descriptor);

        return $descriptor === ['artifact_id' => $this->id, 'count' => $this->memberCount, 'digest' => $this->digest, 'kind' => $this->kind];
    }

    /**
     * Whether the attachment carries its sealed members, as every attachment
     * but one described from its entry does.
     *
     * @return bool
     */
    public function isSealed(): bool
    {
        return $this->members !== null;
    }

    /**
     * The attachment as a bundle carries it, naming the entry it belongs to. An
     * attachment described from its entry has no members to carry and is
     * refused, so it is never stored, queued or spilled.
     *
     * @param  string  $entryId
     * @return array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string}
     *
     * @throws \LogicException
     */
    public function envelopeFor(string $entryId): array
    {
        if ($this->members === null) {
            throw new \LogicException('An attachment described from its entry carries no members and is never stored or encoded.');
        }

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
