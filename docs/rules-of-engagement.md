# Rules of Engagement

The operational agreement for a single assessment: who does what, when, and what
each side can expect. Shared with the client's IT contact before collection.

## Timeline

| Day | What happens | Who |
|---|---|---|
| −7 | Authorization letter and data handling policy sent | Assessor |
| −3 | Signed letter returned | Client |
| −2 | Service account created, delegation granted, prerequisites confirmed | Client IT |
| 0 | Collection window (under one hour) | Assessor |
| +2 | Draft report | Assessor |
| +4 | Walkthrough call (60 minutes) | Both |
| +5 | Final report delivered | Assessor |
| +35 | Client data destroyed, attestation issued | Assessor |

Nothing starts before the signed letter is in hand.

## Client prerequisites

Before the collection window, for each platform in scope (only those named in
section 1 of the signed authorization letter):

**All platforms**

1. A signed authorization letter naming the platform, and these rules of
   engagement agreed.
2. A named technical contact reachable during the collection window.

**Google Workspace**

3. A Google Cloud project with the Admin SDK and Drive APIs enabled.
4. A dedicated service account, with a key issued to the assessor over an agreed
   secure channel — not email.
5. Domain-wide delegation granted for exactly the scopes the assessor supplies
   (`icp verify-scopes` output; also Schedule A of the authorization letter).
6. A named super-administrator for the tool to impersonate. This account is
   never signed into.

**Microsoft 365**

7. A dedicated application registered in the client's own tenant, single-tenant.
8. The certificate the assessor supplies (public key only) uploaded to it. The
   private key never leaves the assessor; no client secret is created.
9. Administrator consent granted for exactly the permissions in Schedule B of
   the authorization letter, and the tenant ID, application ID and certificate
   thumbprint given to the assessor.

**Amazon Web Services**

10. A dedicated role in the client's account holding only the SecurityAudit and
    ViewOnlyAccess policies (Schedule C of the authorization letter).
11. Its trust policy allowing only the assessor's named AWS identity, and only
    with the external ID agreed for this engagement.
12. The role's ARN given to the assessor.

## What happens during collection

- Under one hour of read requests, from the assessor's own infrastructure. The
  tooling is designed for read-only collection: it sends no request that changes
  a setting, and blocks any that would. Two permissions allow more than the
  tooling does (Google's `admin.directory.user.security`, Microsoft's
  `Sites.Read.All`); the authorization letter names them.
- In AWS, the reading is done by Prowler, an open-source scanner, through a role
  holding only AWS's own audit policies (SecurityAudit and ViewOnlyAccess).
  Prowler runs outside the tool's own request guard, so for AWS the evidence of
  read-only behaviour is the client's CloudTrail.
- Read-only is not the same as no effect. The client will see:
  - read requests in the admin audit log (Google, Microsoft) and in CloudTrail
    across all regions (AWS);
  - a sign-in by the assessment service account or application in the sign-in
    logs, and the token requests that go with it;
  - use of the organization's API quota. Microsoft may slow a busy tenant's
    responses (throttling); the tooling waits and retries rather than pressing on.
- The assessor holds a sensitive map of the client's accounts and settings for
  the retention period, protected as the data handling policy describes.
- **We encourage the client to look.** The assessor supplies their own call log
  for comparison, and the scan's start time for filtering CloudTrail.

## Communication

- **Primary contact:** `[name, email, phone]`
- **Assessor contact:** `[name, email, phone]`
- The assessor will notify the technical contact when collection starts and when
  it completes.

## If something looks wrong

If the client observes anything unexpected — unfamiliar API activity, an alert,
a service disruption — during the engagement:

1. Contact the assessor immediately on the number above.
2. If they prefer to act first: remove the service account's domain-wide
   delegation. This revokes all access instantly and needs no coordination.

The assessor will stop work, confirm cessation in writing within one business
day, and investigate.

## Findings requiring immediate attention

If the assessment surfaces something suggesting an active compromise — for
example an administrator account with no second factor showing unfamiliar
sign-in activity, or an unidentified application holding administrative
authority — the assessor will contact the client **within two hours of
discovering it**, ahead of the report.

Judgement call, made in the client's favour: if it plausibly indicates an
incident in progress, the client hears about it that day, not on day 4.

## Out of scope

Not examined, and the report says so on its first page:

- Endpoints, laptops, mobile devices, servers, networks, on-premises systems
- Applications outside the Google Workspace tenant named in the authorization letter
- Penetration testing, exploitation, password testing, social engineering
- Physical security
- Continuous monitoring — this is a point-in-time review
- Policy documentation, staff training, business continuity planning

## Report

- **Executive summary** — one page, plain language, written for a director who
  will read nothing else.
- **Priority action plan** — ten items ordered by risk removed per hour, each
  with an owner and a time estimate.
- **Detailed findings** — every finding names specific accounts or items in the
  client's own environment, with the evidence behind it and the exact remediation
  steps.
- **Framework mapping** — NIST CSF 2.0 context for insurance and grant
  questionnaires. Not an attestation, and labelled as such.
- **Methodology** — the scoring arithmetic in full, so findings can be checked
  and argued with.
- **Coverage notes** — anything that could not be assessed, stated explicitly.
  A check that did not run never appears as a check that passed.

## Re-assessment

A follow-up assessment after remediation shows what was fixed, what remains, and
what is new, along with a trend line. Priced separately; typically quarterly.

## Assumptions

- The client has authority to grant access to the systems named.
- The prerequisites are complete before the collection window.
- The technical contact is reachable during collection.
- Findings are the client's to act on. The assessor does not implement fixes as
  part of this engagement.
