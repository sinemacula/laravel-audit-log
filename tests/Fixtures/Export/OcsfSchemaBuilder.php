<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Export;

/**
 * Builds the OCSF schema the export tests validate against from a checkout of
 * the upstream tag, as normalised files derived from it.
 *
 * Each class is resolved into one file with its parents, profiles, dictionary
 * attributes and reachable objects, keeping only what validation reads. One
 * profile is left out: no exported event applies it, and its upstream text
 * names third-party products.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @phpstan-type RawAttribute array{requirement?: string, type?: string, is_array?: bool, enum?: array<array-key, array{caption?: string}>, profile?: ?string}
 * @phpstan-type RawFile array{name: string, caption: string, extends?: string, category?: string, uid: int, includes: list<string>, attributes: array<string, array{requirement?: string, type?: string, is_array?: bool, enum?: array<array-key, array{caption?: string}>, profile?: ?string}>, constraints?: array<string, list<string>>}
 * @phpstan-type RawDefinition array{name: string, caption: string, category: string, uid: int, attributes: array<string, array{requirement?: string, type?: string, is_array?: bool, enum?: array<array-key, array{caption?: string}>, profile?: ?string}>, constraints: array<string, list<string>>}
 * @phpstan-type RawDictionary array{attributes: array<string, array{requirement?: string, type?: string, is_array?: bool, enum?: array<array-key, array{caption?: string}>, profile?: ?string}>, types: array{attributes: array<string, array{type?: string}>}}
 *
 * @phpstan-import-type Attribute from \Tests\Fixtures\Export\OcsfValidator
 * @phpstan-import-type Definition from \Tests\Fixtures\Export\OcsfValidator
 * @phpstan-import-type Schema from \Tests\Fixtures\Export\OcsfValidator
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @formatter:on
 */
final class OcsfSchemaBuilder
{
    /** @var string The upstream repository. */
    public const string REPOSITORY = 'https://github.com/ocsf/ocsf-schema';

    /** @var string The tag the schema is built from, which is the version the formatter writes. */
    public const string TAG = '1.9.0';

    /** @var string The commit the tag points to. */
    public const string COMMIT = '856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba';

    /** @var string The licence the upstream files are under. */
    public const string LICENCE = 'Apache-2.0';

    /** @var list<string> The profiles kept: every profile the tag has but the one left out. */
    public const array PROFILES = [
        'cloud', 'container', 'data_classification', 'datetime', 'host', 'incident', 'load_balancer', 'network_proxy', 'osint', 'record_integrity', 'security_control', 'trace',
    ];

    /** @var string How the files differ from upstream, as the licence asks of a modified file. */
    public const string MODIFIED = 'Derived from the upstream files, not copied: only what validation reads is kept, one profile is left out, and LICENSE ends in a newline.';

    /** @var list<string> The upstream files copied, with a newline ensured at the end. */
    private const array COPIED = ['LICENSE', 'NOTICE'];

    /** @var string The generic object, whose contents are free. */
    private const string FREE_OBJECT = 'object';

    /** @var array{requirement: string, type: string, is_array: bool} How a class's classification attributes are declared, should a class not declare one. */
    private const array CLASSIFICATION = ['requirement' => 'required', 'type' => 'integer_t', 'is_array' => false];

    /** @var int The flags a file is written with: every array an object, so a map of numbered keys reads back as written. */
    private const int JSON_FLAGS = JSON_FORCE_OBJECT | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    /** @var array<string, string> The checksum of each upstream file read, by its path in the checkout. */
    private array $sources = [];

    /**
     * Constructor.
     *
     * @param  string  $upstream
     */
    public function __construct(

        /** The checkout of the upstream tag. */
        private readonly string $upstream,
    ) {}

    /**
     * Builds the schema from the checkout into the directory, after checking
     * the checkout is the tag's commit and says the tag's version, and returns
     * the files written, by path.
     *
     * @param  string  $upstream
     * @param  string  $target
     * @return array<string, string>
     *
     * @throws \RuntimeException
     */
    public static function build(string $upstream, string $target): array
    {
        $builder = new self(rtrim($upstream, '/'));

        $builder->verify();

        $files = ['version.json' => self::encode(['version' => self::TAG])];

        foreach (self::COPIED as $path) {
            $files[$path] = rtrim($builder->read($path)) . "\n";
        }

        foreach (OcsfValidator::CLASSES as $class) {
            $files[$class . '.json'] = self::encode($builder->resolve($class));
        }

        ksort($files);

        $files['provenance.json'] = self::encode($builder->provenance($files));

        if (!is_dir($target) && !mkdir($target, 0o755, true)) {
            throw new \RuntimeException(sprintf('The directory %s could not be made.', $target));
        }

        foreach ($files as $path => $contents) {
            if (file_put_contents($target . '/' . $path, $contents) === false) {
                throw new \RuntimeException(sprintf('The file %s could not be written.', $path));
            }
        }

        return $files;
    }

    /**
     * The class resolved from the checkout: its classification, its attributes
     * and constraints, every object it can reach, and the type each dictionary
     * type derives from.
     *
     * @param  string  $class
     * @return Schema
     *
     * @throws \JsonException
     * @throws \UnexpectedValueException
     */
    public function resolve(string $class): array
    {
        /** @var RawDictionary $dictionary */
        $dictionary = json_decode($this->read('dictionary.json'), true, 512, JSON_THROW_ON_ERROR);

        /** @var array{attributes: array<string, array{uid: int, caption: string}>} $categories */
        $categories = json_decode($this->read('categories.json'), true, 512, JSON_THROW_ON_ERROR);

        $definition = $this->definition('events', $class);
        $category   = $categories['attributes'][$definition['category']] ?? null;
        $attributes = self::described($dictionary, $definition['attributes']);
        $classUid   = ($category['uid'] ?? 0) * 1000 + $definition['uid'];

        $attributes['class_uid'] = [...$attributes['class_uid'] ?? self::CLASSIFICATION, 'enum' => [$classUid => $definition['caption']]];

        if ($category !== null) {
            $attributes['category_uid'] = [...$attributes['category_uid'] ?? self::CLASSIFICATION, 'enum' => [$category['uid'] => $category['caption']]];
        }

        return [
            'name'         => $definition['name'],
            'caption'      => $definition['caption'],
            'category'     => $definition['category'],
            'category_uid' => $category['uid'] ?? 0,
            'uid'          => $definition['uid'],
            'class_uid'    => $classUid,
            'attributes'   => $attributes,
            'constraints'  => $definition['constraints'],
            'objects'      => $this->objects($dictionary, $attributes),
            'types'        => self::types($dictionary),
        ];
    }

    /**
     * The value as the JSON a file is written as: pretty-printed, every array
     * an object, with a newline at the end.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $value
     * @return string
     *
     * @throws \JsonException
     */
    public static function encode(array $value): string
    {
        return json_encode($value, self::JSON_FLAGS) . "\n";
    }

    /**
     * Refuses a checkout whose HEAD is not the tag's commit, or whose version
     * file does not name the tag.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private function verify(): void
    {
        $head = is_file($this->upstream . '/.git/HEAD') ? trim((string) file_get_contents($this->upstream . '/.git/HEAD')) : '';

        if ($head !== self::COMMIT) {
            throw new \UnexpectedValueException(sprintf('The checkout is not detached at %s, the commit of the tag %s.', self::COMMIT, self::TAG));
        }

        $version = json_decode($this->read('version.json'), true, 512, JSON_THROW_ON_ERROR);

        if ($version !== ['version' => self::TAG]) {
            throw new \UnexpectedValueException(sprintf('The checkout is not version %s.', self::TAG));
        }
    }

    /**
     * The provenance of the files: the repository, the tag, its commit, the
     * licence, how the files were modified, and the checksum of every upstream
     * file read and of every file written.
     *
     * @param  array<string, string>  $files
     * @return array{repository: string, tag: string, commit: string, licence: string, modified: string, sources: array<string, string>, generated: array<string, string>}
     */
    private function provenance(array $files): array
    {
        $sources = $this->sources;

        ksort($sources);

        return [
            'repository' => self::REPOSITORY,
            'tag'        => self::TAG,
            'commit'     => self::COMMIT,
            'licence'    => self::LICENCE,
            'modified'   => self::MODIFIED,
            'sources'    => $sources,
            'generated'  => array_map(static fn (string $contents): string => hash('sha256', $contents), $files),
        ];
    }

    /**
     * The upstream file at the path, its checksum recorded.
     *
     * @param  string  $path
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private function read(string $path): string
    {
        if (!is_file($this->upstream . '/' . $path)) {
            throw new \UnexpectedValueException(sprintf('The schema has no file %s.', $path));
        }

        $contents = (string) file_get_contents($this->upstream . '/' . $path);

        $this->sources[$path] = hash('sha256', $contents);

        return $contents;
    }

    /**
     * The definition with every parent it extends merged beneath it, and the
     * attributes of each profile it includes merged beneath its own.
     *
     * @param  'events'|'objects'  $kind
     * @param  string  $name
     * @return RawDefinition
     *
     * @throws \JsonException
     * @throws \UnexpectedValueException
     */
    private function definition(string $kind, string $name): array
    {
        $file   = $this->file($this->pathOf($kind, $name));
        $parent = isset($file['extends']) ? $this->definition($kind, $file['extends']) : null;
        $own    = $file['attributes'];

        foreach ($file['includes'] as $include) {
            $profile = $this->file($include);
            $tagged  = array_map(static fn (array $attribute): array => [...$attribute, 'profile' => $profile['name']], $profile['attributes']);
            $own     = self::merged($tagged, $own);
        }

        return [
            'name'        => $file['name'],
            'caption'     => $file['caption'],
            'category'    => $file['category'] ?? $parent['category'] ?? '',
            'uid'         => $file['uid'],
            'attributes'  => self::merged($parent['attributes'] ?? [], $own),
            'constraints' => $file['constraints'] ?? $parent['constraints'] ?? [],
        ];
    }

    /**
     * The path of the file defining the object or the class of the name: an
     * object's in `objects/`, and a class's anywhere in `events/`.
     *
     * @param  'events'|'objects'  $kind
     * @param  string  $name
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private function pathOf(string $kind, string $name): string
    {
        if ($kind === 'objects') {
            return 'objects/' . $name . '.json';
        }

        $paths = [...glob($this->upstream . '/events/' . $name . '.json') ?: [], ...glob($this->upstream . '/events/*/' . $name . '.json') ?: []];

        return isset($paths[0])
            ? substr($paths[0], strlen($this->upstream) + 1)
            : throw new \UnexpectedValueException(sprintf('The schema has no class named %s.', $name));
    }

    /**
     * The file, decoded, with its included profiles taken out of its
     * attributes, and every profile left out, and every attribute of one,
     * dropped.
     *
     * @param  string  $path
     * @return RawFile
     *
     * @throws \JsonException
     * @throws \UnexpectedValueException
     */
    private function file(string $path): array
    {
        /** @var array{name?: string, caption?: string, extends?: string, category?: string, uid?: int, attributes?: array<string, list<string>|RawAttribute>, constraints?: array<string, list<string>>} $file */
        $file       = json_decode($this->read($path), true, 512, JSON_THROW_ON_ERROR);
        $attributes = $file['attributes'] ?? [];

        /** @var list<string> $includes */
        $includes = $attributes['$include'] ?? [];

        unset($attributes['$include']);

        /** @var array<string, RawAttribute> $attributes */
        $kept = array_filter($attributes, static fn (array $attribute): bool => !isset($attribute['profile']) || self::isKept($attribute['profile']));

        return [
            'name'    => '',
            'caption' => '',
            'uid'     => 0,
            ...$file,
            'includes'   => array_values(array_filter($includes, static fn (string $include): bool => self::isKept(basename($include, '.json')))),
            'attributes' => $kept,
        ];
    }

    /**
     * Whether the profile is one the schema keeps.
     *
     * @param  string  $profile
     * @return bool
     */
    private static function isKept(string $profile): bool
    {
        return in_array($profile, self::PROFILES, true);
    }

    /**
     * The attributes with each of the overlay's merged over its namesake: its
     * fields replace theirs, and its enum is merged over theirs.
     *
     * @param  array<string, RawAttribute>  $base
     * @param  array<string, RawAttribute>  $overlay
     * @return array<string, RawAttribute>
     */
    private static function merged(array $base, array $overlay): array
    {
        foreach ($overlay as $name => $attribute) {
            $merged = [...$base[$name] ?? [], ...$attribute];

            if (isset($base[$name]['enum'], $attribute['enum'])) {
                $merged['enum'] = array_replace($base[$name]['enum'], $attribute['enum']);
            }

            $base[$name] = $merged;
        }

        return $base;
    }

    /**
     * Each attribute as the dictionary describes it beneath the class's own
     * fields: its requirement, its type, whether it is an array, its enum's
     * captions, the class's merged over the dictionary's, and its profile.
     *
     * @param  RawDictionary  $dictionary
     * @param  array<string, RawAttribute>  $attributes
     * @return array<string, Attribute>
     *
     * @throws \UnexpectedValueException
     */
    private static function described(array $dictionary, array $attributes): array
    {
        $described = [];

        foreach ($attributes as $name => $attribute) {
            $entry = $dictionary['attributes'][$name] ?? throw new \UnexpectedValueException(sprintf('The dictionary has no attribute named %s.', $name));

            $described[$name] = self::describe($entry, $attribute);
        }

        ksort($described);

        return $described;
    }

    /**
     * The attribute as the dictionary's entry describes it beneath the class's
     * own fields.
     *
     * @param  RawAttribute  $entry
     * @param  RawAttribute  $attribute
     * @return Attribute
     */
    private static function describe(array $entry, array $attribute): array
    {
        $merged = [...$entry, ...$attribute];
        $enum   = array_replace($entry['enum'] ?? [], $attribute['enum'] ?? []);

        ksort($enum);

        $described = ['requirement' => $merged['requirement'] ?? 'optional', 'type' => $merged['type'] ?? '', 'is_array' => $merged['is_array'] ?? false];

        if ($enum !== []) {
            $described['enum'] = array_map(static fn (array $value): string => $value['caption'] ?? '', $enum);
        }

        if (isset($attribute['profile'])) {
            $described['profile'] = $attribute['profile'];
        }

        return $described;
    }

    /**
     * Every object the attributes can reach, by name, each resolved as a class
     * is.
     *
     * @param  RawDictionary  $dictionary
     * @param  array<string, Attribute>  $attributes
     * @return array<string, Definition>
     *
     * @throws \JsonException
     * @throws \UnexpectedValueException
     */
    private function objects(array $dictionary, array $attributes): array
    {
        $types   = self::types($dictionary);
        $pending = array_column($attributes, 'type');
        $objects = [];

        while ($pending !== []) {
            $name = array_shift($pending);

            if (isset($types[$name]) || isset($objects[$name]) || $name === self::FREE_OBJECT) {
                continue;
            }

            $definition = $this->definition('objects', $name);
            $described  = self::described($dictionary, $definition['attributes']);

            $objects[$name] = ['attributes' => $described, 'constraints' => $definition['constraints']];
            $pending        = [...$pending, ...array_column($described, 'type')];
        }

        ksort($objects);

        return $objects;
    }

    /**
     * The type each dictionary type derives from at its root: `string_t`,
     * `integer_t`, `long_t`, `float_t`, `boolean_t` or `json_t`.
     *
     * @param  RawDictionary  $dictionary
     * @return array<string, string>
     */
    private static function types(array $dictionary): array
    {
        $declared = $dictionary['types']['attributes'];
        $types    = [];

        foreach (array_keys($declared) as $name) {
            $base = $name;

            while (isset($declared[$base]['type'])) {
                $base = $declared[$base]['type'];
            }

            $types[$name] = $base;
        }

        ksort($types);

        return $types;
    }
}
