# Extending

The package records what it can see on its own, and gives an application or an integration two seams for the rest: a
mapper, which translates an event of its own into a record, and a contributor, which fills in what a record leaves
out. Neither needs the package to know anything about the code that uses it. What the package captures by itself is in
[the automatic-capture guide](automatic-capture.md).

## Extensibility

Every concrete class of the package is `final`. It is extended through the contracts below, each bound in the container
or registered from a service provider's `boot()`; each contract's docblock says what an implementation must keep to:

| Extension point                              | How                                                                                                                                                                                     |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Where records are kept                       | Implement `Contracts\AuditStore` and bind it; bind a `Stores\StackAuditStore` to reach several stores                                                                                   |
| What a store's return means                  | Implement `Contracts\DurableAuditStore` on the store: whether a return is durable, and whose transaction it joins                                                                       |
| Attachments on a custom store                | Implement `Contracts\AcceptsAttachments` on the store, as below: bulk members, read disclosures, export manifests                                                                       |
| Events of the application or another package | Implement `Contracts\EventMapper` and register it with `AuditLog::map()`, as below                                                                                                      |
| What a record leaves out                     | Implement `Contracts\ContextContributor` and register it with `AuditLog::contribute()`                                                                                                  |
| Who a guard without `GuardHelpers` holds     | Implement `Contracts\HeldActorReader` and bind it, as below: the actor, principal, tenant and session it has bound, carried into queued jobs                                            |
| The application's event codes                | Implement `Contracts\DefinesAuditEvents` on a string-backed enum and register it with `AuditLog::define()`                                                                              |
| Encrypted fields                             | Implement `Contracts\FieldEncrypter`, given each value's place, and bind it; the package seals under each owner's key, and `Privacy\NoFieldEncrypter` never encrypts                    |
| How an owner's key is wrapped                | Implement `Contracts\KeyWrapper` and bind it to wrap owners' keys with an external key service; the package binds `Keys\LocalKeyWrapper`                                                |
| Where seals are anchored                     | Set `integrity.anchor.driver`, or implement `Contracts\CheckpointAnchor` and bind it                                                                                                    |
| How long entries are kept and preserved      | Implement `Contracts\RetentionPolicy` and bind it; the package binds `Lifecycle\ConfiguredRetentionPolicy`, which reads `retention.*`                                                   |
| Where verification reads prune records       | Implement `Contracts\PruneLedger` to return the records the pruner journals, as the bound `Lifecycle\JournalPruneLedger` does; any other answer verifies every pruned member as missing |
| Lines for a log or a security tool           | Implement `Contracts\AuditFormatter` and give it to the `Stores\LogAuditStore` the application binds                                                                                    |
| OCSF classes of a code                       | Implement `Contracts\OcsfMapper` and name it in the code's definition with `EventDefinition::ocsf()`                                                                                    |
| Which entries a viewer may read              | Implement `Contracts\AuditAccessPolicy` and bind it; it is asked on every terminal call, and `Access\DenyAllPolicy` denies all                                                          |
| How an entry's encrypted fields are shown    | Implement `Contracts\FieldReader`; asked a page at a time through `readAll()`, under the reveal grant only; the default answers `encrypted`, a decrypting one also `erased`             |
| The time records are stamped with            | Implement `Contracts\Clock` and bind it                                                                                                                                                 |

An integration that binds over a contract only while it still holds the package's default asks
`AuditLogServiceProvider::isPackageDefault($container, $contract)`: true while the contract resolves to the package's
own default, resolved or not, and false for any binding or instance made over it, even of the default's class.

A store that keeps attachments, a bulk operation's subjects, a read's disclosure and an export's manifest, implements
`Contracts\AcceptsAttachments` and returns `true` from `acceptsAttachments()` only when it keeps the attachment and its
entry atomically, both or neither, so an entry never points at an artifact that is not there. It answers from its own
configuration, never from the record. Storing the same id with the same artifact again is a success, and the same id
with a different artifact, or an entry without its own, is a `Stores\RecordConflictException`. A store that does not
implement the contract, or returns `false`, is never handed an attachment: `covering()` is refused while it is
bound, and, since every read of the trail is recorded with a disclosure or an export manifest, in sync mode every page,
count, export and verification is refused with `Querying\AuditReadRefusedException` before anything is queried.

## Mapping another package's events

A mapper implements `Contracts\EventMapper`. It receives the event and a builder, sets the code and the fields it
translates from the event, and returns the same builder, or `null` to skip the event:

```php
public function map(object $event, PendingRecord $record): ?PendingRecord;
```

Register it from a service provider's `boot()`, for the event's class or for a parent class or interface its events
share, leaving out any subtype that should not be recorded:

```php
AuditLog::map(OrderEvent::class, OrderEventMapper::class, except: [OrderViewed::class]);
```

- An event is resolved to the mapping of its exact class first, and otherwise to the one mapping of a parent class or
  interface it has. Two broad mappings that both apply are an ambiguity, never a choice: the capture fails, contained,
  with no mapper named. The answer for a class is worked out once and kept.
- Each entry of `except:` must be a class or interface that exists and is a proper subtype of the mapped one. An event
  that is any of them, or a subtype of one, skips that mapping, the exact-class lookup included.
- `AuditLog::map()` is refused once the application has booted. Mapping a class or interface again with the same mapper
  and exceptions changes nothing, and any other second mapping of it is refused. The package's own events are never
  mapped, nor captured by a broad mapping.
- The first `map()` registers one listener for every event the application dispatches, so a mapped event is captured
  whenever it is dispatched, and an application that maps nothing pays nothing.
- An event the dispatcher never sees, or one a listener of the application's own wants the record of, is captured with
  `AuditLog::capture($event)`, through the same mapping. It returns the record written, or `null`. One event object is
  recorded once, whoever captures it first.
- A mapper is resolved from the container for each capture and keeps no state. Its builder has no recorder, and
  nothing it records is written: calling `record()`, recording through the facade, returning another builder, choosing
  a timing other than `afterTransaction()`, `failClosed()` or `transactional()` are each a contained failure that
  writes nothing. The capture writes the builder returned, at once.
- A mapper of a refusal, such as a failed sign-in or a denied decision, ends its builder with `afterTransaction()`. The
  record then waits for the outermost transaction open on the storage connection to end, and is written whether it
  commits or rolls back, so a refusal that makes the caller roll back is still kept.
- An event that is a bulk operation is mapped with `covering($subjects)` on the builder, as the application records
  one: the record carries the manifest of the subjects, bounded and refused as a bulk operation's is (see
  [Bulk operations](automatic-capture.md#bulk-operations)). A refusal is a contained failure that writes nothing.
- What the mapper's own work sets off is captured as it would be anywhere else: a watched model it saves and a Gate
  check it denies are each recorded by their own capture. Capturing or dispatching the event it is mapping again
  writes nothing, so a mapper never runs inside itself.
- The mapper names its own codes, never one of the package's own codes (those `Capture\Enums\CapturedActivity`
  defines) and never a code derived from the event's class, so renaming the class never changes the trail. An
  integration records under the reserved prefix that fits its activity, such as `mfa.` or `sso.`; an application's own
  events use the application's own prefixes.
- A capture never throws into the code that dispatched the event, but for a failure that ended the application's
  transaction; the automatic-capture guide says what each failure does.

## Recording one row per sign-in

A package with a guard of its own, a session guard named `identity`, fires Laravel's `Login` when it signs a user in,
and its own `Acme\Identity\Events\UserSignedIn` too. Laravel's event is captured by the package, so mapping the other
one alone would record each sign-in twice. Map the package's event, and exclude its guard from core capture.

The mapper records the user as both actor and subject, read from the event, and ties the record to the sign-in attempt
with a correlation id:

<!-- recipe:mapper -->

```php
<?php

namespace App\Audit;

use Acme\Identity\Events\UserSignedIn;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

final readonly class IdentitySignInMapper implements EventMapper
{
    /**
     * The sign-in, by the user who signed in and on them, correlated with the
     * attempt it completed; any other event is skipped.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[\Override]
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        if (!$event instanceof UserSignedIn) {
            return null;
        }

        return $record->event('identity.signed_in')
            ->by($event->user)
            ->on($event->user)
            ->correlatedWith('identity:' . $event->attemptId);
    }
}
```

A mapper that reads the guard, the session reference or the client from its event names them with `viaGuard()`,
`inSession()` and `fromClient()`, so a record written from a queue or after a commit never takes them from another
request. A part the event does not name is left for the contributors.

Register it from a service provider's `boot()`:

<!-- recipe:boot -->

```php
use Acme\Identity\Events\UserSignedIn;
use App\Audit\IdentitySignInMapper;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

public function boot(): void
{
    AuditLog::map(UserSignedIn::class, IdentitySignInMapper::class);
}
```

And leave the guard's own `Login` to the mapper, in `config/audit-log.php`:

<!-- recipe:config -->

```php
'capture' => [
    'laravel' => [
        'except_guards' => ['identity'],
    ],
],
```

- Each sign-in on the `identity` guard is now one row, `identity.signed_in`. A sign-in on any other guard is still
  `authentication.signed_in`, from Laravel's own event.
- The guard is excluded by configuration. The package never looks for another package, so nothing is excluded unless
  the application says so, and `audit-log:check` names an excluded guard `auth.guards` does not configure.
- Use the same shape for any integration whose events say more than Laravel's: map its events, and exclude the guards
  whose Laravel events would repeat them.

## Correlation ids

A correlation id ties a record to other activity, such as the tickets, attempts or jobs of another system. It is
written `<namespace>:<value>`, as in `app:ticket-123`:

```php
AuditLog::event('invoice.approved')->on($invoice)->correlatedWith('app:ticket-123')->record();
```

- The namespace is a lower-case letter followed by up to 31 lower-case letters, digits, underscores or hyphens, so a
  lower-case namespace of up to 32 characters, then a colon.
- The value starts with a character that is not a space. The whole id is 1 to 191 characters, with no control
  characters.
- The id is validated, never cleaned or cut: one that does not fit is an `\InvalidArgumentException` from
  `correlatedWith()`, and the last id given wins. `Records\CorrelationId::isValid()` checks an id first, so a mapper
  can skip one built from outside values rather than lose the record.
- Choose a namespace per source, such as `identity` for the attempts of the recipe above, so ids from two systems never
  collide.

## Contributors

A contributor fills what a record leaves out, such as the principal or the tenant, on every record, the captured ones
included. Register one from a service provider's `boot()` with `AuditLog::contribute()`; it implements
`Contracts\ContextContributor` and fills only what is still a gap, so a value a mapper set, or an actor a capture
names as no one, is never replaced. [The context note](../design/context-resolution.md) says what each contributor may
fill and in what order.

## Guards without GuardHelpers

The ambient actor is read without calling a guard's `user()`, and the package can do that only for a guard using
Laravel's `GuardHelpers`. For any other guard, bind a `Contracts\HeldActorReader`. It is asked about the first guard in
`actor.guards` whose `hasUser()` is true, and returns a `Records\HeldActor` built from what that guard has already
bound, with the principal, tenant and session reference when it knows them:

```php
$this->app->bind(HeldActorReader::class, TokenGuardReader::class);

final class TokenGuardReader implements HeldActorReader
{
    public function read(string $guard, Guard $instance): ?HeldActor
    {
        if (!$instance instanceof TokenGuard) {
            return null;
        }

        return new HeldActor(Reference::to($instance->identity()), tenant: Reference::of('tenant', $instance->tenantId()));
    }
}
```

- `null` leaves the guard to the `GuardHelpers` reading, and an `\InvalidArgumentException` means no ambient actor.
- The reader must read only what the guard holds: never `user()`, never authenticate, never read a request.
- The session reference is an application-owned, non-secret reference, never Laravel's session id.
- The actor and its context fill a record whose actor is open, or already that same actor, and are carried into the
  jobs it queues. A guard the reader reads must not keep its user from one queued job to the next on a worker.
