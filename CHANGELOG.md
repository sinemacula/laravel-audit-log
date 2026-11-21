# Changelog

## 0.1.0 (2026-11-21)

First release. Event-driven audit logging for Laravel: who did what, to what, on whose behalf and from where, as
append-only database rows behind a storage contract.

### Features

* an audit record model with defined event codes
* automatic capture of Laravel's authentication events, and one call to record anything else
* mappers for other packages' events, including bulk operations
* a recorder with ambient context: guard, session, client and correlation id
* database storage with per-row integrity, integrity seals, anchors and verification
* a write path that stores records as they are written or delivers them through a transactional outbox
* a read path with access control
* redaction, data minimisation, privacy and erasure
* retention, pruning and import
* freshness monitoring and production checks
