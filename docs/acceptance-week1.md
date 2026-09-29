# Week 1 acceptance — the manual procedure

Weeks 2 and 3 are verified by `pytest -m acceptance`, offline. Week 1 cannot be,
because it is about infrastructure that has to exist in the real world: a
tenant, a GCP project, a delegation grant.

This is that procedure, and the corrections you need before you start.

---

## The brief's wording needs one fix

> **Done when:** `docker run <image> collect --tenant dev` authenticates and
> writes a snapshot file, and the tenant's audit log shows read operations only.

The first half is right. The second half cannot happen, and not because
anything is broken.

Google Workspace **Admin Audit logs record actions performed in the Admin
console** and write **Admin Activity audit logs only** — and Admin Activity
audit logs contain entries for API calls that *modify* configuration or
metadata. Read calls do not appear there.

So after a clean collection the Admin log will be **empty for your window**. If
you have written "shows read operations only" as your pass condition, you will
spend a day assuming your delegation is broken while it works perfectly.

**Restate it as three checks:**

| # | Where | Expected | What it proves |
|---|---|---|---|
| 1 | Admin log events | **Zero entries** for the window | Nothing was changed. This is the claim you make to clients. |
| 2 | OAuth Token log events | Your app appears | The run happened, and is attributable. |
| 3 | Tool's own call log | 100% GET | Your side of the reconciliation. |

Check 1 is proof of *absence of change*, which is stronger than it first looks
and is exactly what the authorization letter promises.

Check 2 works because **OAuth Token Audit logs track which users are using
which third-party applications in your domain**, and record each time an
application is authorized to access account data.

If you want genuine per-call read logging, that requires Cloud Audit Logs
**Data Access** logs on the GCP project. Those are **disabled by default
because they generate large volumes of data and must be explicitly enabled**.
Turn them on for your own dev tenant so you can see precisely what the tool
touched. Do not ask clients for this.

---

## Before you start: the dedicated impersonation account

Domain-wide delegation attributes every call to the **impersonated
administrator**, not the service account. Impersonate a human super-admin and
your tool's activity is interleaved with that person's real work, indist-
inguishable from it.

Create a super-admin used for nothing else:

```
icp-assessment@yourdevdomain.example
```

Now every log entry attributable to the tool is filterable in one click — by
the client, without your help. That converts "trust our attestation" into
"here's the filter, run it yourself", which is a far better position in a
delivery call. Two minutes of the client's time; put it in the prerequisites.

---

## Step 1 — dev tenant and planted findings

Create a Google Workspace trial tenant and verify a test domain.

Seed it to match `tools/generate_fixtures.py`, which already encodes the
brief's week-1 seeding plan and is what the offline tests assert against:

| Planted | Count | Detected by |
|---|---|---|
| Super-admins | 3 (one with no 2SV, one dormant 120d) | `GWS-ADM-002`, `GWS-MFA-001`; 3 of 32 is under the ceiling, so `GWS-ADM-001` must **not** fire |
| Admins without a security key | 2 (the dormant super-admin, the delegated admin) | `GWS-MFA-003` |
| Users without a second factor | 6, plus the 2 never-signed-in accounts | `GWS-MFA-002` (8 accounts) |
| Stale accounts (>90d) | 5 | `GWS-STA-001` |
| Never signed in | 2 | `GWS-STA-002` |
| Suspended, retaining OAuth grants | 2 | `GWS-STA-003`, `GWS-OAU-001` |
| Over-scoped application | 1 (admin-equivalent, authorized by a super-admin) | `GWS-SVC-001`, `GWS-SVC-002` |
| Admin signed in to Google Cloud SDK | 1 (the delegated admin) | `GWS-SVC-003`, never a third-party app finding |
| Publicly shared Drive items | 3 | `GWS-SHR-001` |
| Broad-scope third-party app | 1 across 12 users | `GWS-OAU-002` |
| Broad app nobody has used in 150 days | 1 | `GWS-OAU-005` (needs usage events in the token log; see note) |
| Unreadable sign-in log | 1 stream | `GWS-LOG-001` |
| Benign sign-in-only app | 1 across 20 users | **must not be flagged** |

`GWS-OAU-005` can only be seeded if your tenant's token audit log records
application *usage*, not just consent. The dev tenant's log holds only
`authorize` and `revoke` events, so there the check correctly reports "not
assessed" — the synthetic fixtures carry the positive case.

The last row is the one people forget. Seed something harmless and widely used,
so you can prove the tool stays quiet about it.

> **If you script the seeding, keep it out of `src/`.** A seeding script makes
> writes, and `tools/verify_readonly.py` will fail the build the moment one
> appears there — correctly. Put it in a separate repository with its own
> credentials. The read-only boundary is worth more than the convenience.

## Step 2 — GCP project and delegation

1. Create a GCP project; enable **Admin SDK API**, **Google Drive API** and
   **Cloud Identity API** (the last one serves Workspace settings such as the
   Drive sharing policy; without it that check becomes a coverage note).
2. Create a service account. Note its **client ID** (the numeric OAuth 2 one).
3. Admin console → Security → Access and data control → API controls →
   **Domain-wide delegation** → Add new.
4. Paste the client ID and the scope list from `icp verify-scopes`, comma-separated.
5. Download a JSON key, then `chmod 600` it. The tool refuses to read a key file
   other users can read.

## Step 3 — configure

```bash
cp .env.example .env
```

```bash
ICP_TENANT_ID=dev
ICP_GOOGLE_ADMIN_SUBJECT=icp-assessment@yourdevdomain.example
ICP_GOOGLE_PRIMARY_DOMAIN=yourdevdomain.example
ICP_HOST_KEY_FILE=/absolute/path/to/service-account.json
ICP_SNAPSHOT_KEY=<output of: icp keygen>
```

## Step 4 — the run

First, prove the delegation grant is complete. This makes seven reads and names
the exact scope if any is missing, which is far better than discovering it forty
seconds into a collection run:

```bash
make image
docker compose run --rm preflight
```

Expect `OK` on the three required surfaces. `DEGRADED` on Reports or Drive is
survivable -- those checks become coverage notes. `FAIL` on users, admin roles,
or OAuth tokens means the assessment is not worth running yet.

Then the collection itself. The brief writes this as
`docker run <image> collect --tenant dev`; in practice the container needs the
environment and the key mounted, which `docker compose run` handles:

```bash
date -u +"%Y-%m-%dT%H:%M:%SZ"        # note the start time
mkdir -p snapshots output && sudo chown -R 10001:10001 snapshots output

make image
time docker compose run --rm collect

date -u +"%Y-%m-%dT%H:%M:%SZ"        # note the end time
```

Record the elapsed time. Week 2's done-when is a full collection in **under
five minutes**, and the long pole is OAuth enumeration: Google exposes tokens
per user, not tenant-wide, so it is one call per account. The collector runs 8
concurrent workers with per-user failure isolation. For a 40-user dev tenant
this is seconds. **Extrapolate before you quote a 500-seat client** — that is
where the five-minute budget gets tested, and if it fails, raising
`_MAX_WORKERS` in `src/icp/collectors/google/oauth.py` is the first lever.

## Step 5 — the three checks

**Check 1 — nothing changed.** Admin console → Reporting → Audit and
investigation → **Admin log events**. Filter to your window. Expect zero rows.
Screenshot it; this is the evidence.

**Check 2 — the run is attributable.** Same tool → **OAuth Token log events**,
filtered to `icp-assessment@`. Your application appears. Logs lag — allow a few
hours before concluding anything.

**Check 3 — your own record.** The run writes
`snapshots/<snapshot-id>.apicalls.jsonl` and a `.manifest.json` beside it:

```bash
cat snapshots/*.manifest.json
```

`verb_counts` must be `{"GET": n}` and nothing else. A single POST, PUT, PATCH
or DELETE here is a defect — investigate before going near a client.

> **Observer effect.** `AuditReadinessCollector` reads the audit logs, so the
> tool's own reads appear in the token log. Expected; don't let it confuse you.

## Step 6 — the offline criteria

```bash
make acceptance     # weeks 2 and 3, no tenant needed
```

---

## Week 1 checklist status

| Item | State |
|---|---|
| Repository scaffold, Docker image, pre-commit, GitHub Actions | **Done** |
| Authorization letter draft | **Done** — `docs/authorization-letter.md`, needs a lawyer |
| Data handling policy draft | **Done** — `docs/data-handling-policy.md` |
| Rules of engagement draft | **Done** — `docs/rules-of-engagement.md` |
| Dev tenant created and seeded | **Yours** |
| GCP project, service account, delegation | **Yours** |
| Independent audit-log confirmation | **Yours** — steps 4–5 above |
| E&O insurance quotes; lawyer review | **Yours — start this week** |

That last row is the one that silently blocks a first paid engagement.
Underwriters take weeks. Nothing about it gets faster by being started later.
