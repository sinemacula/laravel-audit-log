# Changelog

## 1.0.0 (2026-11-19)


### Features

* audit record model and event definitions ([#5](https://github.com/sinemacula/laravel-audit-log/issues/5)) ([1ecc62f](https://github.com/sinemacula/laravel-audit-log/commit/1ecc62fb3ca851ffe19626b64bed6affffc64963))
* automatic capture ([#15](https://github.com/sinemacula/laravel-audit-log/issues/15)) ([33add57](https://github.com/sinemacula/laravel-audit-log/commit/33add576b5f11a12ea33ac68b551bf81e55c35a5))
* database storage with per-row integrity ([#7](https://github.com/sinemacula/laravel-audit-log/issues/7)) ([d30c6c9](https://github.com/sinemacula/laravel-audit-log/commit/d30c6c9c31b58364a83df7a6a9db448b5bc6956e))
* freshness monitoring and production checks ([#19](https://github.com/sinemacula/laravel-audit-log/issues/19)) ([133cde1](https://github.com/sinemacula/laravel-audit-log/commit/133cde1563e1749598b3f161dd5891520a67d61e))
* integrity seals, anchors and verification ([#13](https://github.com/sinemacula/laravel-audit-log/issues/13)) ([c21cbef](https://github.com/sinemacula/laravel-audit-log/commit/c21cbef2ae507881e24573ebf615ed8302c90e8b))
* keep a refusal's record when the transaction around it rolls back ([#33](https://github.com/sinemacula/laravel-audit-log/issues/33)) ([54b4bb2](https://github.com/sinemacula/laravel-audit-log/commit/54b4bb2b30dfd65987f5ffeec4e9b04f5d903acd))
* let a contributor fill the credential ([#37](https://github.com/sinemacula/laravel-audit-log/issues/37)) ([9617172](https://github.com/sinemacula/laravel-audit-log/commit/961717209f3e3d9d7ef797b087a03467eb238ca0))
* let a mapper cover a bulk operation's subjects ([#28](https://github.com/sinemacula/laravel-audit-log/issues/28)) ([098e3c8](https://github.com/sinemacula/laravel-audit-log/commit/098e3c83a2c127d5a8ec02b584c76008d3e6a774))
* let a mapper name the guard, session and client explicitly ([#34](https://github.com/sinemacula/laravel-audit-log/issues/34)) ([cac8860](https://github.com/sinemacula/laravel-audit-log/commit/cac8860123d3a74e6a3f73cf26dc08f77409dfa7))
* let an integration check a correlation id before giving it ([#30](https://github.com/sinemacula/laravel-audit-log/issues/30)) ([35a5093](https://github.com/sinemacula/laravel-audit-log/commit/35a5093a7374195f3024295986513d8e89a8acd4))
* let an integration read the actor a guard without GuardHelpers holds ([#32](https://github.com/sinemacula/laravel-audit-log/issues/32)) ([9e8bac6](https://github.com/sinemacula/laravel-audit-log/commit/9e8bac661a8daa946a3ec75fb4b1ebcb8f06ee6f))
* let an integration tell the package's default binding from another ([#31](https://github.com/sinemacula/laravel-audit-log/issues/31)) ([badcda5](https://github.com/sinemacula/laravel-audit-log/commit/badcda53338ef06eef3f28fbe5cbf0b765133c4a))
* lifecycle and import ([#17](https://github.com/sinemacula/laravel-audit-log/issues/17)) ([def5ec5](https://github.com/sinemacula/laravel-audit-log/commit/def5ec597d6e41b9b89643cd0b9c34ee11c610d4))
* note a disabled prune schedule while the prune could delete ([#48](https://github.com/sinemacula/laravel-audit-log/issues/48)) ([4bbc2d8](https://github.com/sinemacula/laravel-audit-log/commit/4bbc2d82434a9fdb60ea3c733638968d1be032d4))
* privacy and erasure ([#18](https://github.com/sinemacula/laravel-audit-log/issues/18)) ([dc13a92](https://github.com/sinemacula/laravel-audit-log/commit/dc13a925f292f63615eb575632f012dcfc13e08b))
* read path and access control ([#16](https://github.com/sinemacula/laravel-audit-log/issues/16)) ([f5cc7f8](https://github.com/sinemacula/laravel-audit-log/commit/f5cc7f891f29659b4cfe17cf495664cb129dc7d9))
* recorder and ambient context ([#8](https://github.com/sinemacula/laravel-audit-log/issues/8)) ([61cad43](https://github.com/sinemacula/laravel-audit-log/commit/61cad43ebb80b7f05b77c39f21ef47700de7fa83))
* redaction and data minimisation ([#9](https://github.com/sinemacula/laravel-audit-log/issues/9)) ([916adbd](https://github.com/sinemacula/laravel-audit-log/commit/916adbde4a3dee436c8b2e8aa92fc736ed2c7434))
* write path and delivery ([#12](https://github.com/sinemacula/laravel-audit-log/issues/12)) ([7222b21](https://github.com/sinemacula/laravel-audit-log/commit/7222b213ad30d036058a85135e02ef338a5fdb28))


### Bug Fixes

* bound import inserts by bytes so a chunk fits the MySQL packet ([#98](https://github.com/sinemacula/laravel-audit-log/issues/98)) ([a7d90fd](https://github.com/sinemacula/laravel-audit-log/commit/a7d90fd07ad4ef1f6745c2da6e96d647181d0366))
* clear the qlty findings and drop configuration the shared source provides ([#29](https://github.com/sinemacula/laravel-audit-log/issues/29)) ([4891dbd](https://github.com/sinemacula/laravel-audit-log/commit/4891dbd60e5b8dbdfeffd4933d078701be7aaa2a))
* dispatch AuditWriteFailed when a drain final attempt fails unexpectedly ([#81](https://github.com/sinemacula/laravel-audit-log/issues/81)) ([243e81a](https://github.com/sinemacula/laravel-audit-log/commit/243e81a777578e8ad08bbcadc2b3fde28eac5b95))
* drop commit flushes with their transaction and pin performance budgets ([#97](https://github.com/sinemacula/laravel-audit-log/issues/97)) ([20e9a97](https://github.com/sinemacula/laravel-audit-log/commit/20e9a979d25a3a75cc2b065e344860ce1e333053))
* fail a replay of a non-empty file with no spill lines ([#80](https://github.com/sinemacula/laravel-audit-log/issues/80)) ([2575bbf](https://github.com/sinemacula/laravel-audit-log/commit/2575bbf0323b714412eed49863edce0e8dc7ebaf))
* leave the Performance suite out of the full mutation run ([#54](https://github.com/sinemacula/laravel-audit-log/issues/54)) ([d629bb8](https://github.com/sinemacula/laravel-audit-log/commit/d629bb8a192ee828d96ea5e1be54fc14f798e48f))
* mint timed UUIDv7s without moving Laravel's shared generator ([#38](https://github.com/sinemacula/laravel-audit-log/issues/38)) ([a77967c](https://github.com/sinemacula/laravel-audit-log/commit/a77967c9bc95c03f42b5f3d388a51e1b2dd27a77))
* never re-store a pruned lifecycle record on reconcile ([#92](https://github.com/sinemacula/laravel-audit-log/issues/92)) ([a1ab25e](https://github.com/sinemacula/laravel-audit-log/commit/a1ab25ec087fb098d63e1231c6940af1afcc5f86))
* read the lifecycle lock on the maintenance connection in audit-log:check ([#94](https://github.com/sinemacula/laravel-audit-log/issues/94)) ([15511d3](https://github.com/sinemacula/laravel-audit-log/commit/15511d37abbe36e61e436ec5173891c50415cd5b))
* report a decorated default as not the package default ([#88](https://github.com/sinemacula/laravel-audit-log/issues/88)) ([ce9e383](https://github.com/sinemacula/laravel-audit-log/commit/ce9e38387781338ae6f3c68ecc3550338a8dde62))
* split the full mutation run into four parts over shared coverage ([#61](https://github.com/sinemacula/laravel-audit-log/issues/61)) ([e6bdc6b](https://github.com/sinemacula/laravel-audit-log/commit/e6bdc6b89364b3455e4b699f0529ff5208c50221))
* treat an empty table setting the same for every table ([#89](https://github.com/sinemacula/laravel-audit-log/issues/89)) ([9404088](https://github.com/sinemacula/laravel-audit-log/commit/9404088057e964895e8d9a779f1a21325a0b35bb))
