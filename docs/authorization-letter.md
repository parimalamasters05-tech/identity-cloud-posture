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

`[Keep only the platforms in scope for this engagement; delete the others here,
in sections 2, 4 and 5, and their schedules. Access to a platform not listed
here is not authorised, whatever credentials the Client provides.]`

- **Google Workspace:** the tenant for the primary domain `[domain.example]`
  (customer ID `[customer_id]`).
- **Microsoft 365:** the Microsoft Entra tenant `[tenant name]`
  (tenant ID `[tenant-id-guid]`, primary domain `[domain.example]`).
- **Amazon Web Services:** the AWS account `[12-digit account ID]`
  (`[account alias]`), identity and storage-exposure settings only, in all regions.

The Client confirms that it owns or lawfully controls these environments and has
the authority to grant this permission.

## 2. What the Assessor will do

- **Google Workspace:** retrieve configuration and metadata through Google's
  official administrative APIs, using a service account restricted to the
  scopes in Schedule A. All of them are read-only except one, which Schedule A
  names and explains.
- **Microsoft 365:** retrieve configuration and metadata through Microsoft
  Graph, Microsoft's official administrative interface, using an application
  registered in the Client's tenant and limited to the permissions in
  Schedule B. All of them are read-only; one could open file contents, which
  Schedule B names and explains.
- **Amazon Web Services:** read configuration with Prowler, an open-source
  assessment tool, through a role in the Client's account that holds only the
  AWS-managed policies in Schedule C. Prowler's results are then imported into
  the Assessor's tooling, which itself makes no request to AWS.
- On every platform, the Assessor's tooling performs read and list operations
  only.
- Store the collected data in encrypted form, analyse it, and produce a written
  report.

## 3. What the Assessor will not do

The Assessor will **not**:

- Change any setting, account, permission, or piece of data in the environment.
- Access the contents of any email, document, file, chat message, stored object,
  or database.
- Attempt to guess, test, crack, phish, or otherwise obtain any user's password.
- Perform penetration testing, vulnerability exploitation, social engineering,
  denial-of-service testing, or any other active security testing.
- Access systems outside the scope listed in section 1, including endpoints,
  networks, and on-premises infrastructure.
- Retain client data beyond the period in section 6.

## 4. Access period

Access is authorised from `[start date]` to `[end date]` only. Collection is
expected to take under one hour within that window.

The Client may revoke this authorisation at any time, for any platform, by
removing the access below and notifying the Assessor in writing. The Assessor
will confirm cessation within one business day.

- **Google Workspace:** remove the service account's domain-wide delegation.
- **Microsoft 365:** delete the application registration, or remove its
  administrator consent.
- **Amazon Web Services:** delete the assessment role, or remove the Assessor
  from its trust policy.

## 5. Credentials

The Assessor will not request, accept, or use any individual user's password or
second factor, on any platform. Access is granted only as follows:

- **Google Workspace:** the Client creates a dedicated service account and
  grants domain-wide delegation for exactly the scopes in Schedule A.
- **Microsoft 365:** the Client registers a dedicated application in its own
  tenant, uploads the certificate (public key only) the Assessor supplies, and
  grants administrator consent for exactly the permissions in Schedule B. The
  private key stays with the Assessor; no client secret is created.
- **Amazon Web Services:** the Client creates a dedicated role holding only the
  policies in Schedule C, which the Assessor can assume only with the external
  ID agreed for this engagement (`[external ID]`). The Assessor's AWS identity
  used to assume it has no other rights in the Client's account.

The Client should remove this access once the assessment is complete.

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

## Schedule A — Google Workspace scopes requested

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

## Schedule B — Microsoft 365 permissions requested

Application permissions on Microsoft Graph, granted by administrator consent.
Every request the Assessor's tooling sends is checked before it leaves: only
reads, and only to a fixed list of reviewed Graph endpoints; any request for a
file's contents is refused.

```
Application.Read.All
AuditLog.Read.All
Directory.Read.All
Policy.Read.All
RoleManagement.Read.Directory
SharePointTenantSettings.Read.All
Sites.Read.All
User.Read.All
UserAuthenticationMethod.Read.All
```

All are read-only. Some of the data they read depends on the tenant's licence
(sign-in history, for example, needs Microsoft Entra ID P1); where it is not
available, the report says so instead of omitting it.

**Note on `Sites.Read.All`:** Microsoft offers no permission that lists who a
OneDrive or SharePoint file is shared with without also allowing its contents
to be read. The Assessor's tooling reads only file names and sharing links, and
refuses, before sending, any request for a file's contents. Each request is
recorded so the Client can check this in its own Entra audit and sign-in logs.

---

## Schedule C — Amazon Web Services access requested

A role in the Client's account, assumable by the Assessor only with the agreed
external ID, holding only these AWS-managed policies:

```
arn:aws:iam::aws:policy/SecurityAudit
arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
```

AWS designed both for security review and viewing configuration; neither allows
any change. The reading is done by Prowler, an open-source tool, outside the
Assessor's own request controls; one of the checks run with every scan confirms
that the role holds only these two policies. Every request is recorded in the
Client's own CloudTrail, and the Assessor supplies the scan's start time so the
Client can review it.

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
