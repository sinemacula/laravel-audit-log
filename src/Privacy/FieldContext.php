<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Where a value an encrypter seals will be stored, and for whom: the entry it
 * belongs to, its path within the entry, the log the entry is signed into, the
 * record's tenant and category, and every owner the record encrypts for.
 *
 * The entry, the path and the log are what an envelope is bound to: a sealed
 * value authenticates only at the place it was sealed for, so an envelope
 * copied to another entry, another path or another log does not open. The
 * tenant and the category, with an owner, name the key a value is sealed under,
 * so materially different obligations never share a key. The owners list every
 * owner the record encrypts for, each once, sorted by type and then id, so an
 * encrypter can fetch every key the record needs at once, on its first value.
 *
 * A path is the column, `properties`, `context` or `ip`, then each list index
 * as an integer at the element's stored index, and each map key as PHP keys it,
 * an integer from 0 as that integer and any other key as a string, so a
 * member's path is the same whether its container is stored as a map or a list:
 * `["properties","card","last4"]`, `["properties","items",0,"iban"]`, or
 * `["ip"]` alone. Every part is checked as the context is built, and anything
 * else is refused with an `InvalidArgumentException` that never names the path
 * or an owner.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FieldContext
{
    /** @var list<string> The columns a path may start with. */
    public const array COLUMNS = ['properties', 'context', 'ip'];

    /** @var string A lower-case UUID: an entry id. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string A log id: 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit. */
    private const string LOG_ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/';

    /** @var string Why a path is refused; it names nothing of the path. */
    private const string MALFORMED_PATH = 'A field context\'s path must be a list of `properties`, `context` or `ip`, then map keys and list'
        . ' indexes, each a string or an integer from 0; `ip` stands alone.';

    /** @var non-empty-list<int|string> Where in the entry the value sits: the column, then each map key and list index. */
    public array $path;

    /** @var list<\SineMacula\Laravel\AuditLog\Records\Reference> Every owner the record encrypts for, each once, sorted by type and then id. */
    public array $owners;

    /**
     * Constructor.
     *
     * @param  string  $entryId
     * @param  array<array-key, int|string>  $path
     * @param  string  $logId
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  string  $category
     * @param  array<array-key, \SineMacula\Laravel\AuditLog\Records\Reference>  $owners
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The id of the entry the value belongs to, a lower-case UUID. */
        public string $entryId,

        // Where in the entry the value sits; checked, never repaired.
        #[\SensitiveParameter]
        array $path,

        /** The id of the log the entry is signed into. */
        public string $logId,

        /** The record's tenant, or `null` for a tenantless record. */
        public ?Reference $tenant,

        /** The category of the record's definition. */
        public string $category,

        // Every owner the record encrypts for, in any order and repeated
        // freely; kept each once, sorted.
        #[\SensitiveParameter]
        array $owners,
    ) {
        if (preg_match(self::UUID_PATTERN, $entryId) !== 1) {
            throw new \InvalidArgumentException('A field context\'s entry id must be a lower-case UUID.');
        }

        $this->path = self::checkedPath($path);

        if (preg_match(self::LOG_ID_PATTERN, $logId) !== 1) {
            throw new \InvalidArgumentException('A field context\'s log id must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.');
        }

        if (preg_match(EventDefinition::CATEGORY_PATTERN, $category) !== 1) {
            throw new \InvalidArgumentException('A field context\'s category must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.');
        }

        $this->owners = self::distinctAndSorted($owners);
    }

    /**
     * The path, refused unless it is a list starting with a column, its `ip`
     * standing alone, and its other parts map keys or list indexes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $path
     * @return non-empty-list<int|string>
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedPath(#[\SensitiveParameter] array $path): array
    {
        if ($path === [] || !array_is_list($path) || !in_array($path[0], self::COLUMNS, true) || ($path[0] === 'ip' && count($path) > 1)) {
            throw new \InvalidArgumentException(self::MALFORMED_PATH);
        }

        $checked = [$path[0]];

        foreach (array_slice($path, 1) as $segment) {
            if (!is_string($segment) && (!is_int($segment) || $segment < 0)) {
                throw new \InvalidArgumentException(self::MALFORMED_PATH);
            }

            $checked[] = $segment;
        }

        return $checked;
    }

    /**
     * The owners, each once, sorted bytewise by type and then by id; anything
     * that is not a reference is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $owners
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function distinctAndSorted(#[\SensitiveParameter] array $owners): array
    {
        $distinct = [];

        foreach ($owners as $owner) {
            if (!$owner instanceof Reference) {
                throw new \InvalidArgumentException('A field context\'s owners must each be a reference.');
            }

            // A reference holds no control character, so a NUL between its
            // parts keys it unambiguously
            $distinct[$owner->type . "\0" . $owner->id] = $owner;
        }

        usort($distinct, static fn (Reference $left, Reference $right): int => strcmp($left->type, $right->type) ?: strcmp($left->id, $right->id));

        return $distinct;
    }
}
