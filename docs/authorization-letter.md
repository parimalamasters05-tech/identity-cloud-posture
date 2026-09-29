# Authorization to Assess — template

> **This is a starting draft, not legal advice.** Have a lawyer in your
> jurisdiction review it before you send it to anyone. The cost of that review
> is small compared to the cost of accessing a client's systems without
> defensible written permission.
>
> Nothing in this engagement begins until a signed copy is returned. Not the
> service account creation, not a test collection, nothing. Accessing someone
> else's systems without authorization is a criminal matter in most
> jurisdictions regardless of how helpful your intent was.

---

**Engagement reference:** `ENG-YYYY-NNN`
**Date:** `____________________`

## Parties

**Client:** `[Legal entity name]`, `[registered address]`
**Assessor:** `[Your legal entity name]`, `[registered address]`

## 1. Authorization granted

The Client authorises the Assessor to perform a read-only configuration review
of the following environments, and no others:

- Google Workspace tenant for the primary domain `[domain.example]`
  (customer ID `[customer_id]`)

The Client confirms that it owns or lawfully controls these environments and has
the authority to grant this permission.

## 2. What the Assessor will do

- Retrieve configuration and metadata through official Google administrative
  APIs, using a service account restricted to the scopes listed in Schedule A.
  All of them are read-only except one, which Schedule A names and explains.
  The Assessor's tooling performs read and list operations only.
- Store that data in encrypted form, analyse it, and produce a written report.

## 3. What the Assessor will not do

The Assessor will **not**:

- Change any setting, account, permission, or piece of data in the environment.
- Access the contents of any email, document, file, or chat message.
- Attempt to guess, test, crack, phish, or otherwise obtain any user's password.
- Perform penetration testing, vulnerability exploitation, social engineering,
  denial-of-service testing, or any other active security testing.
- Access systems outside the scope listed in section 1, including endpoints,
  networks, and on-premises infrastructure.
- Retain client data beyond the period in section 6.

## 4. Access period

Access is authorised from `[start date]` to `[end date]` only. Collection is
expected to take under one hour within that window.

The Client may revoke this authorisation at any time by removing the service
account's domain-wide delegation and notifying the Assessor in writing. The
Assessor will confirm cessation within one business day.

## 5. Credentials

The Client will create a dedicated service account and grant domain-wide
delegation for the scopes in Schedule A. The Assessor will not request, accept,
or use any individual user's password or second factor.

The Client should remove the delegation once the assessment is complete.

## 6. Data handling

Governed by the Assessor's Data Handling Policy, provided alongside this letter.
In summary:

- Configuration and metadata only. No message or file content is collected.
- Encrypted at rest using AES-256-GCM.
- Retained for no more than **[30] days** after report delivery, then destroyed.
- A written deletion attestation is issued at destruction.

## 7. Deliverables

- A written report: executive summary, prioritised action plan, detailed
  findings with evidence, framework mapping, and methodology.
- The machine-readable findings file and the underlying configuration snapshot.
- A walkthrough call of up to `[60]` minutes.

## 8. Limitations, stated plainly

This engagement is a **point-in-time technical configuration review**. It is
**not**:

- an audit, and the Assessor is not an auditor;
- a certification or attestation against any standard or framework;
- a guarantee that the environment is secure, or that all weaknesses have been
  found;
- legal advice, or advice on regulatory compliance.

Any mapping to a framework such as NIST CSF 2.0 is provided as context for the
Client's own questionnaires and must not be presented as a statement of
compliance.

## 9. Confidentiality

Each party will keep the other's confidential information confidential. The
report and its findings are the Client's confidential information. The
Assessor's methodology, scope taxonomy, remediation content library, and
software remain the Assessor's property.

## 10. Liability

`[To be drafted by your lawyer. This clause and your professional indemnity /
errors-and-omissions cover are what stand between a disputed finding and a
personally ruinous claim. Start the insurance application in week 1 — under-
writers routinely take several weeks, and this is the single most common thing
that delays a first engagement.]`

---

## Schedule A — scopes requested

Generate the current list with `icp verify-scopes` and paste it here. Every
scope on it is on an allowlist that the Assessor's tooling enforces before
authenticating, and state-changing HTTP methods (POST, PUT, PATCH, DELETE) are
additionally blocked at the transport layer.

Required:

```
https://www.googleapis.com/auth/admin.directory.domain.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.orgunit.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.reports.usage.readonly
https://www.googleapis.com/auth/drive.metadata.readonly
```

Drive access is limited to file names, owners and sharing settings; the scope
does not allow reading the contents of any file.

Optional (if not granted, only the named item is skipped):

```
https://www.googleapis.com/auth/cloud-identity.policies.readonly   (Drive sharing settings)
https://www.googleapis.com/auth/admin.directory.customer.readonly  (organization name for the report cover)
```

**Note on `admin.directory.user.security`, the one scope that is not
read-only:** Google publishes no read-only variant of it. It is the only scope
that allows listing the third-party applications staff have authorised, which
is one of the most valuable parts of this assessment. It would also permit
revoking those authorisations and signing users out; the Assessor's tooling
does neither. The tooling blocks state-changing requests at the transport layer
and records every API call made, so that the Client can verify read-only
behaviour independently in their own admin audit log.

---

## Signatures

**For the Client**

Name: `____________________`  Title: `____________________`

Signature: `____________________`  Date: `____________________`

The signatory confirms they are authorised to grant access to the systems named
in section 1.

**For the Assessor**

Name: `____________________`  Title: `____________________`

Signature: `____________________`  Date: `____________________`
