<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * What a bulk operation affected, in its canonical form and bounded, before it
 * is sealed: each subject once, as the type and id pair a reference stores.
 *
 * The canonical form is the JSON list of `[type, id]` pairs, de-duplicated on
 * the exact pair and sorted bytewise on the type and then on the id, encoded
 * with fixed flags, so the same subjects in any order and with any repetition
 * give the same bytes and the same digest, a lower-case hex SHA-256 of them.
 * Its id is a lower-case UUID version 7 made once, so a retry, a drain and a
 * replay of its record carry the same artifact.
 *
 * Nothing is ever truncated: more unique subjects than the cap, a canonical
 * form over the byte bound, or more subjects read than four times the cap,
 * duplicates included, is refused. The bytes are counted as the subjects
 * arrive, so an endless or oversize input stops early.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Manifest
{
    /** @var string The kind of artifact a manifest is sealed as. */
    public const string KIND = 'bulk';

    /** @var int How many subjects may be read for each one the cap allows, duplicates included. */
    public const int MAX_INPUT_FACTOR = 4;

    /** @var int The flags the canonical form is encoded with: those every stored JSON column uses. */
    public const int JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

    /** @var int Bytes of the canonical form that are not a member: its opening and closing brackets. */
    private const int BRACKET_BYTES = 2;

    /** @var string What separates a type from its id in the key a member is de-duplicated on; never in either. */
    private const string SEPARATOR = "\0";

    /** @var int How deep a canonical form nests: the list, its pairs and their strings. */
    private const int DEPTH = 3;

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  int  $count
     * @param  string  $digest
     * @param  string  $canonical
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The artifact's id: a lower-case UUID version 7, made once. */
        public string $id,

        /** How many members the manifest holds, each once, at least one. */
        public int $count,

        /** Lower-case hex SHA-256 of the canonical form. */
        public string $digest,

        /** The canonical form: the sorted JSON list of each member's type and id. */
        #[\SensitiveParameter]
        public string $canonical,
    ) {
        if ($count < 1) {
            throw new \InvalidArgumentException('A bulk operation names at least one subject.');
        }
    }

    /**
     * The manifest of the subjects, each a model, which becomes its reference,
     * or a reference, kept once whatever the order or repetition they come in.
     *
     * @param  iterable<array-key, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference>  $subjects
     * @param  int  $maxMembers
     * @param  int  $maxBytes
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public static function of(#[\SensitiveParameter] iterable $subjects, int $maxMembers, int $maxBytes): self
    {
        $members = [];
        $read    = 0;
        $bytes   = self::BRACKET_BYTES - 1;

        foreach ($subjects as $subject) {
            $reference = self::referenceOf($subject);
            $key       = $reference->type . self::SEPARATOR . $reference->id;

            if (!isset($members[$key])) {
                $members[$key] = [$reference->type, $reference->id];
                $bytes += strlen(json_encode($members[$key], self::JSON_FLAGS)) + 1;
            }

            self::checkBounds(++$read, count($members), $bytes, $maxMembers, $maxBytes);
        }

        $canonical = self::encode(array_values($members));

        return new self(Str::uuid7()->toString(), count($members), hash('sha256', $canonical), $canonical);
    }

    /**
     * The canonical form of the members, which are distinct: sorted bytewise on
     * the type and then on the id, and encoded with the manifest's flags.
     *
     * @param  list<array{0: string, 1: string}>  $members
     * @return string
     *
     * @throws \JsonException
     */
    public static function encode(#[\SensitiveParameter] array $members): string
    {
        usort($members, self::compare(...));

        return json_encode($members, self::JSON_FLAGS);
    }

    /**
     * The count and digest of a plaintext that is exactly a canonical form: a
     * non-empty list of type and id pairs, both strings, in strictly increasing
     * order, which encodes back to the same bytes; `null` for any other
     * plaintext.
     *
     * @param  string  $plaintext
     * @return ?array{count: int, digest: string}
     *
     * @throws \JsonException
     */
    public static function readCanonical(#[\SensitiveParameter] string $plaintext): ?array
    {
        $decoded = self::decoded($plaintext);

        if (!self::isOrderedList($decoded) || json_encode($decoded, self::JSON_FLAGS) !== $plaintext) {
            return null;
        }

        return ['count' => count($decoded), 'digest' => hash('sha256', $plaintext)];
    }

    /**
     * The descriptor a bulk record signs at `properties._audit.manifest`: the
     * artifact's id, the digest and the count.
     *
     * @return array{artifact_id: string, digest: string, count: int}
     */
    public function descriptor(): array
    {
        return ['artifact_id' => $this->id, 'digest' => $this->digest, 'count' => $this->count];
    }

    /**
     * The subject's reference: a model's own, or the reference given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $subject
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function referenceOf(#[\SensitiveParameter] mixed $subject): Reference
    {
        if ($subject instanceof Reference) {
            return $subject;
        }

        if ($subject instanceof Model) {
            return Reference::to($subject);
        }

        throw new \InvalidArgumentException(sprintf('A bulk operation\'s subjects are models or references; one is %s.', get_debug_type($subject)));
    }

    /**
     * Refuse more subjects read than four times the cap, more members than the
     * cap, or a canonical form of more bytes than the bound.
     *
     * @param  int  $read
     * @param  int  $count
     * @param  int  $bytes
     * @param  int  $maxMembers
     * @param  int  $maxBytes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkBounds(int $read, int $count, int $bytes, int $maxMembers, int $maxBytes): void
    {
        if ($count > $maxMembers) {
            throw new \InvalidArgumentException(sprintf('A bulk operation names at most %d subjects, the `audit-log.capture.bulk.max_members` setting.', $maxMembers));
        }

        if ($read > $maxMembers * self::MAX_INPUT_FACTOR) {
            $message = 'A bulk operation reads at most %d subjects, duplicates included: four times the `audit-log.capture.bulk.max_members` setting.';

            throw new \InvalidArgumentException(sprintf($message, $maxMembers * self::MAX_INPUT_FACTOR));
        }

        if ($bytes > $maxBytes) {
            $message = 'A bulk operation\'s manifest must encode to at most %d bytes, the `audit-log.capture.bulk.max_bytes` setting.';

            throw new \InvalidArgumentException(sprintf($message, $maxBytes));
        }
    }

    /**
     * The plaintext decoded, or `null` when it is not JSON or nests deeper than
     * a canonical form.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $plaintext
     * @return mixed
     */
    private static function decoded(#[\SensitiveParameter] string $plaintext): mixed
    {
        try {
            return json_decode($plaintext, true, self::DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }

    /**
     * Whether the decoded value is a non-empty list of type and id pairs in
     * strictly increasing order, so with no member twice.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $decoded
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-list<array{0: string, 1: string}> $decoded
     */
    private static function isOrderedList(#[\SensitiveParameter] mixed $decoded): bool
    {
        if (!is_array($decoded) || $decoded === [] || !array_is_list($decoded)) {
            return false;
        }

        $previous = null;

        foreach ($decoded as $member) {
            if (!self::isPair($member) || ($previous !== null && self::compare($previous, $member) >= 0)) {
                return false;
            }

            $previous = $member;
        }

        return true;
    }

    /**
     * Whether the decoded member is a type and id pair: a list of exactly two
     * strings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $member
     * @return bool
     *
     * @phpstan-assert-if-true array{0: string, 1: string} $member
     */
    private static function isPair(#[\SensitiveParameter] mixed $member): bool
    {
        if (!is_array($member) || array_keys($member) !== [0, 1]) {
            return false;
        }

        return is_string($member[0]) && is_string($member[1]);
    }

    /**
     * Which of two members comes first: bytewise on the type, then on the id.
     *
     * @param  array{0: string, 1: string}  $a
     * @param  array{0: string, 1: string}  $b
     * @return int
     */
    private static function compare(#[\SensitiveParameter] array $a, #[\SensitiveParameter] array $b): int
    {
        return strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1]);
    }
}
