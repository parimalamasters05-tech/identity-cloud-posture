# Data Handling Policy

> Provided to every client alongside the authorization letter. Have a lawyer
> review it before you rely on it commercially, and check it against your own
> obligations under GDPR, UK GDPR, CCPA, HIPAA, or whatever applies where you
> and your clients operate.
>
> Everything described here is implemented in the tooling, not merely promised.
> Where that is true, the implementing code is named, so this document can be
> checked rather than taken on trust.

## 1. What is collected

**Configuration and metadata only.** Specifically:

- Account records: email address, display name, creation and last sign-in
  timestamps, suspension state, organizational unit
- Administrative role definitions and assignments
- Second-factor enrollment state and, where available, whether a security key
  is registered
- Third-party application authorizations: application name, client ID, and the
  scopes granted
- Group names, addresses, and membership counts
- Metadata for Drive items already shared publicly: name, type, owner,
  modification date
- Whether administrative, sign-in, and token audit streams return data

## 2. What is never collected

- The contents of any email, document, spreadsheet, file, or chat message
- Attachments, or any link that would retrieve file content
- Passwords, second-factor secrets, OAuth access or refresh tokens
- Home addresses, personal phone numbers, recovery contacts, employee IDs, or
  custom HR schema fields
- Anything outside the Google Workspace tenant named in the authorization letter

This is structural rather than procedural. Each collector declares an explicit
allowlist of fields and everything else is discarded before it reaches storage
(`src/icp/collectors/base.py`), and no data model in the system has a field
capable of holding message or file content. Both properties are asserted by
`tests/security/test_data_minimization.py`, which runs on every commit.

## 3. How it is stored

- **Encryption at rest:** AES-256-GCM. The snapshot identifier is bound into the
  ciphertext as additional authenticated data, so a file cannot be substituted
  for another engagement's snapshot without failing decryption.
  (`src/icp/security/crypto.py`)
- **Key management:** the encryption key is held in a secret manager, never on
  the same medium as the encrypted data, and never written to disk by the tool.
- **File permissions:** owner-read/write only (0600), in a 0700 directory.
- **Full-disk encryption** is enabled on every device that handles client data.
- **Logs are redacted** at the logging boundary: email local parts are masked,
  private keys, bearer tokens, and long secrets are removed
  (`src/icp/security/redaction.py`).

## 4. How long it is kept

| Item | Retention |
|---|---|
| Configuration snapshot | **30 days** after report delivery |
| Machine-readable findings | 30 days, unless a retainer is agreed |
| The report itself | Kept per the engagement letter; the Client keeps their own copy |
| API call audit trail | 12 months, as evidence of read-only behaviour |

Where a retainer includes quarterly comparison, snapshots are retained for the
term of the retainer so that change over time can be shown. That is agreed in
writing, in advance, and is the only circumstance in which retention exceeds 30
days.

## 5. Destruction

Destruction is performed by `icp purge`, which derives each file's age from the
timestamp in its filename rather than its filesystem modification time —
copying a file between machines resets mtime and would otherwise silently extend
retention beyond what was promised.

File contents are overwritten before unlinking. We state honestly that on
copy-on-write and flash-backed filesystems overwriting does not guarantee the
original blocks are unrecoverable; the real controls are the short retention
window and full-disk encryption.

A **deletion attestation** is issued to the Client on request, recording what was
destroyed, when, by whom, and by what method.

## 6. Access

Client data is accessible only to the named assessor delivering the engagement.
It is not shared with subcontractors, not used to train any model, not used for
benchmarking or marketing, and not aggregated across clients in any form that
could identify a client or an individual.

## 7. Credentials

- The assessor never requests, accepts, or uses an individual user's password or
  second factor.
- Service account keys are stored with 0600 permissions; the tooling refuses to
  read a key file that other users can read
  (`src/icp/security/credentials.py`).
- Keys are never committed to version control. This is enforced by
  `.gitignore`, a `detect-private-key` pre-commit hook, and a gitleaks scan in
  CI.
- The Client is advised to remove the service account's domain-wide delegation
  once the assessment is complete.

## 8. Read-only operation

The tooling enforces read-only operation in three independent ways: a scope
allowlist checked before any credential is constructed; a transport wrapper that
raises on any state-changing HTTP method before a request is sent; and a static
analyser in CI that fails the build if a write-capable API call exists anywhere
in the source.

Every API call made during collection is recorded and delivered alongside the
snapshot, so the Client can reconcile it against their own admin audit log
rather than taking our word for it.

## 9. Personal data

Account records are personal data under GDPR and equivalent regimes. In that
framing the Client is the controller and the assessor is a processor acting on
documented instructions — the authorization letter.

- Processing is limited to delivering the agreed assessment.
- No transfer outside `[your jurisdiction]` occurs without the Client's
  agreement.
- Data subject requests are the Client's to handle; the assessor will assist and
  will confirm deletion on request.
- `[A Data Processing Agreement should be executed where GDPR applies. Have
  your lawyer prepare one.]`

## 10. Incidents

If client data held by the assessor is lost, exposed, or accessed without
authorization, the assessor will notify the Client's named contact **within 24
hours** of becoming aware, with what is known at that point, and will follow up
with a written account of what happened and what was done about it.

## 11. Contact

`[Name]`, `[role]` — `[email]` — `[phone]`
