<?php

declare(strict_types = 1);

namespace Tests\Unit\Export;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Export\OcsfValidator;

/**
 * Tests for the offline OCSF validator the formatter tests rely on: it accepts
 * a valid event of each pinned class, refuses each invalid fixture with the one
 * error it names, holds each class as resolved through its `extends` chain and
 * the profiles it includes, with a class's enum merged over the dictionary's,
 * and checks types, objects, arrays, constraints and profiles.
 *
 * It covers nothing: the validator is a test fixture, not the package's code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class OcsfValidatorTest extends TestCase
{
    /** @var string The invalid fixtures. */
    private const string INVALID = __DIR__ . '/../../Fixtures/Export/ocsf/invalid';

    /** @var array<string, array<string, array<string, string>|int|string>|int|string> A valid Base Event, as the formatter writes one. */
    private const array BASE_EVENT = [
        'activity_id'   => 0,
        'activity_name' => 'Unknown',
        'category_name' => 'Uncategorized',
        'category_uid'  => 0,
        'class_name'    => 'Base Event',
        'class_uid'     => 0,
        'message'       => 'invoice.approved',
        'metadata'      => [
            'event_code'    => 'invoice.approved',
            'logged_time'   => 1793534401654,
            'original_time' => '2026-11-01T12:00:00.123456Z',
            'product'       => ['name' => 'laravel-audit-log', 'vendor_name' => 'Sine Macula'],
            'uid'           => '01932b4e-8a40-7000-8000-000000000001',
            'version'       => '1.9.0',
        ],
        'severity'    => 'Informational',
        'severity_id' => 1,
        'status'      => 'Success',
        'status_id'   => 1,
        'time'        => 1793534400123,
        'type_name'   => 'Base Event: Unknown',
        'type_uid'    => 0,
        'unmapped'    => ['category' => 'finance'],
    ];

    /** @var array<string, array<string, array<string, string>|string>|int|string> What makes the Base Event a valid API Activity update, in place of its classification and `unmapped`. */
    private const array API_ACTIVITY = [
        'activity_id'   => 3,
        'activity_name' => 'Update',
        'category_name' => 'Application Activity',
        'category_uid'  => 6,
        'class_name'    => 'API Activity',
        'class_uid'     => 6003,
        'type_name'     => 'API Activity: Update',
        'type_uid'      => 600303,
        'actor'         => ['user' => ['uid' => 'user:42']],
        'api'           => ['operation' => 'invoice.approved'],
        'src_endpoint'  => ['ip' => '203.0.113.7'],
    ];

    /**
     * A valid Base Event has no errors.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAcceptsAValidBaseEvent(): void
    {
        self::assertSame([], OcsfValidator::pinned()->errors(self::BASE_EVENT));
    }

    /**
     * A valid API Activity has no errors.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAcceptsAValidApiActivity(): void
    {
        self::assertSame([], OcsfValidator::pinned()->errors(self::apiActivity()));
    }

    /**
     * Rows of `[fixture, the one error it has]`: every invalid fixture.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideInvalidFixtures(): iterable
    {
        yield from [
            'missing time'                => ['missing-time', 'time: required attribute is missing'],
            'missing metadata version'    => ['missing-metadata-version', 'metadata.version: required attribute is missing'],
            'severity outside enum'       => ['severity-outside-enum', 'severity_id: 7 is not in its enum'],
            'class uid a string'          => ['class-uid-a-string', 'class_uid: expected integer_t, got string'],
            'undeclared attribute'        => ['undeclared-attribute', 'invoice_total: attribute is not declared'],
            'type uid mismatch'           => ['type-uid-mismatch', 'type_uid: must be class_uid * 100 + activity_id, 0, not 1'],
            'api activity without an api' => ['api-activity-without-api', 'api: required attribute is missing'],
        ];
    }

    /**
     * Each invalid fixture has exactly the one error it was written to have.
     *
     * @param  string  $fixture
     * @param  string  $error
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideInvalidFixtures')]
    public function testRefusesEachInvalidFixture(string $fixture, string $error): void
    {
        $event = json_decode((string) file_get_contents(self::INVALID . '/' . $fixture . '.json'), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($event);
        self::assertSame([$error], OcsfValidator::pinned()->errors($event));
    }

    /**
     * Every invalid fixture on disk is one the test names, so none is left
     * unchecked.
     *
     * @return void
     */
    public function testEveryInvalidFixtureIsChecked(): void
    {
        $files = array_map(static fn (string $file): string => basename($file, '.json'), glob(self::INVALID . '/*.json') ?: []);

        $named = array_column(iterator_to_array(self::provideInvalidFixtures()), 0);

        sort($named);

        self::assertSame($named, $files);
    }

    /**
     * API Activity is resolved through Application Activity to Base Event: it
     * keeps Base Event's attributes and its parent's category, takes its own
     * uid, and its own attribute overrides an included profile's.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function testResolvesTheExtendsChain(): void
    {
        $schema = OcsfValidator::schema('api_activity');

        $classification = [$schema['name'], $schema['caption'], $schema['category'], $schema['category_uid'], $schema['uid'], $schema['class_uid']];

        self::assertSame(['api_activity', 'API Activity', 'application', 6, 3, 6003], $classification);
        self::assertSame(['requirement' => 'required', 'type' => 'timestamp_t', 'is_array' => false], $schema['attributes']['time']);
        self::assertSame(['requirement' => 'required', 'type' => 'api', 'is_array' => false], $schema['attributes']['api']);
        self::assertSame(['requirement' => 'required', 'type' => 'cloud', 'is_array' => false, 'profile' => 'cloud'], $schema['attributes']['cloud']);
        self::assertSame(['requirement' => 'recommended', 'type' => 'trace', 'is_array' => false, 'profile' => 'trace'], $schema['attributes']['trace']);
        self::assertSame([6003 => 'API Activity'], $schema['attributes']['class_uid']['enum'] ?? null);
        self::assertSame([6 => 'Application Activity'], $schema['attributes']['category_uid']['enum'] ?? null);
        self::assertSame('long_t', $schema['types']['timestamp_t']);
        $actor = ['process', 'user', 'iam_role', 'invoked_by', 'session', 'application', 'app_name', 'app_uid'];

        self::assertSame($actor, $schema['objects']['actor']['constraints']['at_least_one'] ?? null);
    }

    /**
     * Base Event, which extends nothing and is in no listed category, is class
     * 0 in category 0, and an attribute it has only from a profile keeps that
     * profile, where API Activity declares the same attribute as its own.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function testResolvesBaseEventToClassZero(): void
    {
        $schema = OcsfValidator::schema('base_event');

        self::assertSame([0, 0, 0], [$schema['category_uid'], $schema['uid'], $schema['class_uid']]);
        self::assertSame([0 => 'Base Event'], $schema['attributes']['class_uid']['enum'] ?? null);
        self::assertSame([0 => 'Uncategorized'], $schema['attributes']['category_uid']['enum'] ?? null);
        self::assertSame(['requirement' => 'optional', 'type' => 'api', 'is_array' => false, 'profile' => 'cloud'], $schema['attributes']['api']);
    }

    /**
     * A class's enum is merged over the dictionary's: API Activity's four
     * activities join the dictionary's unknown and other, and Base Event's
     * success and failure join the dictionary's statuses.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function testMergesAClassEnumOverTheDictionary(): void
    {
        $activity = OcsfValidator::schema('api_activity')['attributes']['activity_id']['enum'] ?? null;
        $status   = OcsfValidator::schema('base_event')['attributes']['status_id']['enum']     ?? null;

        self::assertSame([0 => 'Unknown', 1 => 'Create', 2 => 'Read', 3 => 'Update', 4 => 'Delete', 99 => 'Other'], $activity);
        self::assertSame([0 => 'Unknown', 1 => 'Success', 2 => 'Failure', 99 => 'Other'], $status);
    }

    /**
     * A class the pinned schema has not is refused.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function testRefusesAClassTheSchemaHasNot(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The pinned schema has no class named no_such_class.');

        OcsfValidator::schema('no_such_class');
    }

    /**
     * Rows of `[what replaces part of a valid Base Event, the one error it
     * gives]`: each kind of check the validator makes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideChecks(): iterable
    {
        yield from [
            'a class no class has'              => [['class_uid' => 4242], 'class_uid: no pinned class has the uid 4242'],
            'a derived type'                    => [['time' => '1793534400123'], 'time: expected timestamp_t, got string'],
            'an object that is no map'          => [['metadata' => 'metadata'], 'metadata: expected metadata, got string'],
            'an object that is a list'          => [['metadata' => ['1.9.0']], 'metadata: expected metadata, got array'],
            'an attribute of an object'         => [['metadata' => [...self::metadata(), 'version' => 190]], 'metadata.version: expected string_t, got int'],
            'an array that is no array'         => [['observables' => 'x'], 'observables: expected an array of observable'],
            'a member of an array'              => [['observables' => ['x']], 'observables[0]: expected observable, got string'],
            'a profile the event does not name' => [['cloud' => ['provider' => 'aws']], 'cloud: attribute is not declared'],
            'a profile the event names'         => [['metadata' => [...self::metadata(), 'profiles' => ['cloud']]], 'cloud: required attribute is missing'],
        ];
    }

    /**
     * Each check finds its one error in an otherwise valid Base Event.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $replacement
     * @param  string  $error
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideChecks')]
    public function testFindsEachKindOfError(array $replacement, string $error): void
    {
        self::assertSame([$error], OcsfValidator::pinned()->errors([...self::BASE_EVENT, ...$replacement]));
    }

    /**
     * A class whose uid is not its category's times 1000 plus its own is named,
     * whatever its enum says.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAClassOutsideItsCategoryIsNamed(): void
    {
        self::assertSame(
            ['category_uid: 6 is not in its enum', 'class_uid: must be category_uid * 1000 + 0, 6000, not 0'],
            OcsfValidator::pinned()->errors([...self::BASE_EVENT, 'category_uid' => 6]),
        );
    }

    /**
     * An object's constraints are checked: an actor must name at least one of
     * the things it may be.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testChecksAnObjectsConstraints(): void
    {
        $errors = OcsfValidator::pinned()->errors([...self::apiActivity(), 'actor' => ['authorizations' => []]]);

        self::assertSame(['actor: at_least_one of process, user, iam_role, invoked_by, session, application, app_name, app_uid'], $errors);
    }

    /**
     * Whatever `unmapped` holds, and whatever a profile the event names
     * declares, is accepted: `unmapped` is free, and a profile's attributes are
     * declared once it applies.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testUnmappedAndAnAppliedProfileAreDeclared(): void
    {
        $event = [
            ...self::BASE_EVENT,
            'metadata' => [...self::metadata(), 'profiles' => ['cloud']],
            'cloud'    => ['provider' => 'aws'],
            'unmapped' => ['anything' => ['nested' => [1, 'two', null, true]], 'at' => 'all'],
        ];

        self::assertSame([], OcsfValidator::pinned()->errors($event));
    }

    /**
     * The valid Base Event's metadata.
     *
     * @return array<string, array<string, string>|int|string>
     */
    private static function metadata(): array
    {
        $metadata = self::BASE_EVENT['metadata'];

        self::assertIsArray($metadata);

        return $metadata;
    }

    /**
     * A valid API Activity: the Base Event with API Activity's classification
     * and attributes, and no `unmapped`.
     *
     * @return array<string, array<string, array<string, string>|int|string>|int|string>
     */
    private static function apiActivity(): array
    {
        $event = [...self::BASE_EVENT, ...self::API_ACTIVITY];

        unset($event['unmapped']);

        return $event;
    }
}
