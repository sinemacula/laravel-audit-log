# Contributing

Contributions are welcome via GitHub pull requests. This guide covers the expectations for working on this package.

## Requirements

- PHP 8.3+
- Composer 2

## Getting Started

```bash
git clone git@github.com:sinemacula/laravel-audit-log.git
cd laravel-audit-log
composer install
```

## Development Workflow

### Branching

Branch from `master` using the appropriate prefix:

| Prefix      | Purpose                          |
|-------------|----------------------------------|
| `feature/`  | New functionality                |
| `bugfix/`   | Bug fixes                        |
| `hotfix/`   | Urgent production fixes          |
| `refactor/` | Refactoring without new features |
| `test/`     | Test-only changes                |
| `docs/`     | Documentation-only changes       |
| `chore/`    | Tooling, CI, dependencies        |

### Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Prefix your commit messages accordingly:

```text
feat: record the credential alongside the actor
fix: write the audit record after the transaction commits
test: add a write budget test for the database store
chore: update qlty configuration
```

Pull request titles must follow the same convention - and they are the ones that matter most: PRs are
squash-merged, so the title becomes the commit on `master`, and release-please derives the changelog and
the next version from those commits.

### Code Quality

All code must pass static analysis before submission:

```bash
composer check    # Static analysis and lint checks via qlty (PHPStan, PHP-CS-Fixer, CodeSniffer)
composer format   # Format the codebase via qlty
composer smells   # Advisory code smells (duplication, complexity)
```

### Testing

Run the full test suite before submitting:

```bash
composer test                 # Run the test suite in parallel using Paratest
composer test:coverage        # With clover coverage report
composer test:mutation        # Mutation gate scoped to your diff against master
composer test:mutation:full   # Full mutation run, no threshold
```

Individual suites:

```bash
composer test:unit          # Unit tests
composer test:feature       # Feature tests
composer test:integration   # Integration tests
composer test:performance   # Performance budget tests
```

Single test file or method:

```bash
vendor/bin/phpunit tests/Feature/AuditLogServiceProviderTest.php
vendor/bin/phpunit --filter testMethodName tests/Unit/SomeTest.php
```

The suites run on in-memory SQLite unless `DB_CONNECTION` names another engine. CI runs every suite on MySQL 8.4 and
PostgreSQL 17 as well; to run them locally, start the engine and point the tests at it with a user that can create
databases and users and grant them privileges (`root` or `postgres`), since each paratest worker creates a database of
its own and the least-privilege tests create their own users:

```bash
export DB_CONNECTION=mysql DB_HOST=127.0.0.1 DB_PORT=3306 DB_DATABASE=laravel_audit_log_test DB_USERNAME=root DB_PASSWORD=password
vendor/bin/paratest --exclude-testsuite Performance # every other suite, in parallel
vendor/bin/phpunit --testsuite Performance          # the budgets, serially
```

For PostgreSQL set `DB_CONNECTION=pgsql`, `DB_PORT=5432` and `DB_USERNAME=postgres`. The Performance suite times its
budgets, so run it serially with `phpunit`, never with `paratest`.

### Standards

- PHPStan level 8 compliance
- Full type hints on all public method parameters and return types
- PHPDoc on all methods and classes
- Namespaces keep to the dependency rules in `tests/Unit/Architecture/NamespaceDependenciesTest.php`: each rule in
  `RULES` (and `FRAMEWORK_RULES` for the framework) says which namespaces may not name which others, and a class that
  moves or a dependency that narrows changes a rule there, never the test's scanner. Every name a rule gives must exist,
  so a rule left behind by a move fails.
- Nothing shipped (`src`, `config`, `database`, `lang`, `docs`, the README or `composer.json`) names, requires or
  detects another Sine Macula package; `PackageBoundaryTest` and `DocumentationTest` hold the code and the docs to it.
  Examples use neutral names such as `invoice.approved` and `app:ticket-123`.
- New code is expected to ship with tests covering the behavioural surface; the package's mutation-testing gate
  (`composer test:mutation`) is the enforced floor. Behaviour that spans the capture lifecycle (events, the write path,
  transactions, queues) should be covered by integration tests that exercise the package the way a consuming
  application does.

## Pull Requests

- Title the PR as a Conventional Commit - the squash-merge makes it the commit that drives the changelog
- Keep changes minimal and scoped to a single concern
- Do not change static analysis or formatting configuration without prior discussion
