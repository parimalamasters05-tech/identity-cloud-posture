# Identity & Cloud Posture Health Check

A read-only assessment tool that inspects an organization's Google Workspace
identity and access configuration and produces a prioritized, plain-language
remediation report.

**The product is the report.** The software exists to make that report cheap to
produce repeatedly and impossible to get wrong in the same way twice. Two
competent engineers can build identical collectors; what a client pays for is
the judgement encoded in `config/remediation.yaml` and
`config/scope_severity_taxonomy.yaml`.

Version 0.1.0 covers Google Workspace only. Microsoft 365 and AWS are planned
and the architecture is built for them, but nothing is stubbed in a way that
pretends they work.

---

## The one thing to understand first

Everything hangs off a single architectural decision:

```
collectors  ->  SNAPSHOT  ->  normalizers  ->  rules  ->  risk  ->  report
   (API)       (timestamped,    (provider     (platform-   (scoring)  (HTML/PDF)
                 immutable)      specific)     agnostic)
```

Collectors write raw API responses to a timestamped snapshot. **Nothing
downstream of the snapshot ever talks to a provider API again.** That single
constraint buys four things that are each expensive to retrofit:

- **Offline development.** Every rule test runs against frozen fixtures, with no
  tenant and no credentials. The whole suite runs in about two seconds.
- **Delta reporting for free.** Re-run next quarter, diff the findings, sell the
  retainer. This is the difference between a one-time fee and recurring revenue.
- **Evidence traceability.** Every sentence in the report points back to the
  exact API response that justified it, which is what you need when a skeptical
  IT contact pushes back live on a walkthrough call.
- **Cheap platform expansion.** Adding Microsoft 365 in week 5 means writing
  `collectors/microsoft/`. It does not mean touching `rules/`, `risk/`, or
  `reporting/`.

---

## Read-only, enforced three ways

The core promise to a client is that this tool cannot change anything in their
tenant. That promise is enforced in three independent places, so no single
mistake can break it:

| # | Control | Where | When |
|---|---------|-------|------|
| 1 | Scope allowlist — only reviewed scopes may be requested (all read-only except `admin.directory.user.security`; see `SCOPE_CAVEATS`) | `src/icp/security/scopes.py` | Before a credential is constructed |
| 2 | Transport guard — POST/PUT/PATCH/DELETE raise before a byte leaves the process | `src/icp/security/readonly.py` | Every HTTP request |
| 3 | Static verifier — AST scan fails the build if a write-capable call exists | `tools/verify_readonly.py` | CI and pre-commit |

A fourth, weaker check runs after every collection: the recorded call log is
asserted to contain no unsafe verb, and written alongside the snapshot as a
JSONL trail you can reconcile against the client's own admin audit log.

```bash
icp verify-scopes        # print the allowlist for the client prerequisites sheet
python tools/verify_readonly.py
pytest -m security       # the controls that must never regress
```

---

## Quick start (no tenant needed)

The repository ships a fixture set representing a dev tenant with deliberately
planted problems, so you can see the whole pipeline before you have a client.

```bash
pip install -e ".[dev]"
icp run --fixtures --client-name "Riverside Community Trust" --assessor "Your Name"
```

That collects from fixtures, runs 19 rules, and writes an HTML and PDF report to
`output/`. Expect 24 findings: 4 critical, 11 high, 8 medium, 1 low.

PDF generation needs WeasyPrint's system libraries. If they are missing you get
the HTML and a clear message rather than a stack trace. Docker avoids the
question entirely — see below.

---

## Docker

The image exists mainly so PDF generation is reproducible rather than a
per-laptop yak-shave, and so each engagement gets a clean, disposable
environment. Given what a snapshot contains, that is worth having.

```bash
make image                      # docker build -t icp:local .
make demo                       # full offline pipeline, no credentials
docker compose run --rm demo    # the same thing
```

The demo runs with `network_mode: none`. It genuinely cannot reach anything,
which is a more convincing demonstration of the offline path than a claim in a
README.

### `docker run` directly

The brief's done-when command is `docker run <image> collect --tenant dev`. That
is the right shape -- `ENTRYPOINT` is `icp`, so everything after the image name
is passed straight through -- but a container starts with no environment and no
filesystem, so it needs three things supplied:

```bash
docker run --rm \
  --env-file .env \
  -e ICP_GOOGLE_KEY_FILE=/run/secrets/sa-key.json \
  -v "$PWD/snapshots:/work/snapshots" \
  -v "/absolute/path/to/service-account.json:/run/secrets/sa-key.json:ro" \
  icp:local collect --tenant dev
```

`--tenant dev` alone satisfies the tenant identifier; `ICP_TENANT_ID` is not
needed when the flag is given. `docker compose run --rm collect` wraps all of
the above, which is why the compose file exists.

### Real engagement

```bash
cp .env.example .env
$EDITOR .env                    # also set ICP_HOST_KEY_FILE to your key's path

docker compose run --rm preflight # verify delegation FIRST -- seconds, seven reads
docker compose run --rm collect   # the ONLY service that collects data
docker compose run --rm assess    # network_mode: none
docker compose run --rm report    # network_mode: none
docker compose run --rm purge
```

Collection is the only stage with a network. Everything downstream works on
local files, and the compose file enforces that at the container level — which
turns the architecture's central claim into something you can check rather than
something you have to trust.

Anything else: `docker compose run --rm icp list-rules`.

### How the image is hardened

- Runs as UID 10001, never root.
- Read-only root filesystem; `/tmp` is a small tmpfs for font caches.
- All capabilities dropped, `no-new-privileges` set.
- Multi-stage build, so no compiler ships in the runtime image.
- `snapshots/` and `output/` are empty mount points. A snapshot must never end
  up in a layer that could be pushed to a registry, and CI asserts they are
  empty.
- The build runs `icp verify-scopes`, `icp list-rules` and a WeasyPrint render,
  so a broken scope allowlist, an unregistered rule, or a missing font library
  fails the build rather than the engagement.

### The one thing that will bite you

Bind-mounted host directories must be writable by **UID 10001**:

```bash
mkdir -p snapshots output && sudo chown -R 10001:10001 snapshots output
```

Without this you get a permission error on the first write. The alternative —
running the container as root — defeats the point.

On Docker Desktop for macOS and Windows this is handled for you and no `chown`
is needed.

---

## Running against a real tenant

### 1. Client-side prerequisites

The client's super-administrator creates a Google Cloud project, a service
account, and grants domain-wide delegation for exactly the scopes that
`icp verify-scopes` prints. Nothing else.

### 2. Paperwork first

Do not run anything before `docs/authorization-letter.md` is signed. It is not
optional and it is not a formality — it is the document that makes this
assessment legal rather than unauthorised access.

### 3. Configure

```bash
cp .env.example .env
$EDITOR .env
icp keygen              # snapshot encryption key -> ICP_SNAPSHOT_KEY
chmod 600 /path/to/service-account.json
```

The tool refuses to read a key file other users can read. `Settings` holds
credential *locations*, never values, so key material cannot appear in a
traceback.

### 4. Run

```bash
set -a; source .env; set +a

icp preflight                                      # do this first, every time
icp collect                                        # the ONLY command that touches the tenant
icp assess                                         # rules, offline, against the snapshot
icp report --client-name "Client Name" --assessor "Your Name"
```

Stages are separate on purpose. Once `collect` has run, you can iterate on
analysis and report wording all week without going near the client's
environment again.

### 5. Quarterly re-run

```bash
icp delta --previous output/<first>__findings.json --current output/<second>__findings.json
```

### 6. Destroy the data

```bash
icp purge --operator "Your Name"
```

Deletes snapshots past `ICP_RETENTION_DAYS` and writes a deletion attestation to
hand to the client. The retention window must match what
`docs/data-handling-policy.md` promises them.

---

## What it checks

Nineteen rules across the seven check families:

| Family | Rules | What it answers |
|---|---|---|
| MFA coverage | `GWS-MFA-001..003` | Who can get in with a password alone, and whose second factor can be phished |
| Admin role sprawl | `GWS-ADM-001..002` | How many people hold the keys, and whether any of them stopped showing up |
| Stale accounts | `GWS-STA-001..003` | Accounts still working that nobody is using |
| Service account privilege | `GWS-SVC-001..002` | Software connections holding administrative authority |
| External sharing | `GWS-SHR-001..002` | Files reachable by anyone with a link |
| Logging readiness | `GWS-LOG-001..002` | Whether an incident six weeks ago could be reconstructed |
| **Third-party OAuth grants** | `GWS-OAU-001..005` | **What staff already consented to hand over** |

The last family is the differentiator. Most posture tools check MFA and admin
counts; almost none surface the transcription app that can read every mailbox it
was given, still authorized by someone who left last year. That finding lands in
a room in a way an MFA statistic does not, and `GWS-OAU-001` — grants held by
suspended accounts — is the most reliable "I had no idea" moment in the
catalogue.

`icp list-rules` prints the current set with impact/exposure inputs.

---

## How findings are scored

Transparent arithmetic, never a black box. Clients challenge rankings, and being
able to show the working is what wins that conversation.

```
risk score = base(severity) x privilege x blast radius x confidence
```

- **base** comes from an explicit impact x exposure matrix in
  `config/risk_matrix.yaml`, printed verbatim in the report's methodology appendix.
- **privilege** (x1.6) applies if any affected account is an administrator. One
  privileged account lifts the whole finding, because an attacker only needs one.
- **blast radius** grows logarithmically and caps at x2.0. Forty affected users
  is worse than four, but not ten times worse — linear scaling would bury every
  single-account critical under tenant-wide noise.
- **confidence** discounts findings inferred from indirect signals rather than
  read from an authoritative field, and the report says which is which.

The priority action plan is ordered by **risk removed per hour**, not severity.
In an under-resourced IT team the work that actually gets done is the work that
fits in an afternoon, so cheap high-value fixes belong at the top. The plan is
also deduplicated by remediation: five findings fixed by one action are one
item, because the plan lists *actions*, not *problems*.

When a ranking looks wrong, change the YAML and note it in the report's version
history. Do not add an unexplained adjustment in code.

---

## Layout

```
src/icp/
  collectors/google/     nine collectors; raw API responses only, no judgement
  normalizers/           provider JSON -> normalized tenant view
  models/                Identity, OAuthGrant, Resource, Finding, Snapshot
  rules/                 19 rules, one module per check family, platform-agnostic
  risk/                  scope taxonomy, severity matrix, scoring, ranking
  reporting/             Jinja2 templates, executive summary, PDF renderer
  delta/                 assessment-over-time comparison (the retainer)
  storage/               encrypted snapshots, findings, retention enforcement
  security/              scopes, transport guard, redaction, crypto, credentials
config/
  scope_severity_taxonomy.yaml   OAuth scope -> blast radius. The IP.
  remediation.yaml               the content library. The product.
  risk_matrix.yaml               impact x exposure -> severity
  framework_mapping.yaml         NIST CSF 2.0 subcategories
fixtures/google/         frozen dev-tenant data with planted findings
docs/                    authorization letter, data handling policy, rules of engagement
tools/                   fixture generator, read-only verifier
Dockerfile               multi-stage, non-root, build-time smoke test
docker-compose.yml       demo / collect / assess / report / purge
Makefile                 install, test, security, lint, verify, image, demo
```

`collectors/microsoft/` and `collectors/aws/` exist as empty packages with a note
about what lands there. Core models were kept provider-agnostic from day one so
week 5 is "add a collector", not a refactor.

---

## Development

```bash
pytest                       # 223 tests, ~6s, fully offline
pytest -m security           # the controls that must never regress
pytest -m integration        # full pipeline through the CLI
ruff check src tests tools
mypy
bandit -c pyproject.toml -r src -ll
pip-audit --strict
python tools/generate_fixtures.py    # regenerate fixtures
```

The test worth knowing about is `tests/rules/test_planted_findings.py`. Every
problem seeded into the fixture tenant must be detected, and nothing benign may
be flagged — `Payroll Portal`, a sign-in-only app held by 20 users, must never
appear in the OAuth findings. False positives are asserted with the same force
as false negatives, because a tool that flags harmless things destroys its own
credibility just as fast as one that misses real ones.

### Adding a rule

1. Write it in the relevant `src/icp/rules/` module, decorated with `@register`.
2. Add remediation content to `config/remediation.yaml`. The renderer **refuses
   to build a report** if any finding lacks content, so this is not optional.
3. Add the planted case to `tools/generate_fixtures.py` and assert it in
   `tests/rules/test_planted_findings.py`.
4. Add a negative case proving it does not fire on a healthy tenant.

### Editorial standard for remediation content

Non-negotiable, because this is the part clients forward to their board:

- `impact` must be understandable by a non-technical executive director in one
  sentence, with no unexplained acronyms.
- `steps` must let a junior IT person finish the job without further research.
  Every step names the actual admin console path.
- Never write "consider reviewing your posture."

---

## Boundaries

This is a **technical configuration review**. It is not an audit, a
certification, or an attestation against any framework, and it is not legal
advice. The report says so on its first page and again on the framework mapping
page. Selling an "audit" without being an auditor is a real liability, not a
wording preference.

Configuration and metadata only. No message or file content is collected — not
as a policy that could be relaxed, but structurally: there is no field in any
model capable of holding a file body, and
`tests/security/test_data_minimization.py` asserts it stays that way.

A check that could not run is reported explicitly as a coverage note, never
omitted. A permission failure degrades one collector; it must never look like a
clean result.
