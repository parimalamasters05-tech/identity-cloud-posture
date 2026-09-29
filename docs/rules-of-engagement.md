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

Before the collection window:

1. A Google Cloud project with the Admin SDK and Drive APIs enabled.
2. A dedicated service account, with a key issued to the assessor over an agreed
   secure channel — not email.
3. Domain-wide delegation granted for exactly the scopes the assessor supplies
   (`icp verify-scopes` output; also Schedule A of the authorization letter).
4. A named super-administrator for the tool to impersonate. This account is
   never signed into.
5. A named technical contact reachable during the collection window.

## What happens during collection

- Under one hour of read-only API calls, from the assessor's own infrastructure.
- No impact on service availability, and no change to any setting.
- A few hundred read requests appear in the client's admin audit log. **We
  encourage the client to look.** The assessor supplies their own call log for
  comparison.

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
