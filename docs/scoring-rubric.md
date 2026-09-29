# Scoring rubric

How every finding gets its severity, its score, and its place in the action
plan. The numbers live in [`config/risk_matrix.yaml`](../config/risk_matrix.yaml)
(version 2026.09.2). This page explains them. The report's methodology section
prints the same matrix, and the evidence appendix shows each finding's
arithmetic.

## 1. Severity: impact × exposure

Each rule declares two numbers from 1 to 5:

- **Impact**: how much damage the problem enables if it's exploited.
  1 is negligible, 5 is organization-wide compromise.
- **Exposure**: how reachable the problem is.
  1 needs local access, 5 is reachable from the internet with no sign-in.

The matrix maps the pair to a severity:

| Impact \ Exposure | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| **5** | Medium | High | High | Critical | Critical |
| **4** | Medium | Medium | High | High | Critical |
| **3** | Low | Medium | Medium | Medium | High |
| **2** | Low | Low | Low | Medium | Medium |
| **1** | Info | Info | Info | Low | Low |

Severity is the report's claim about urgency. Nothing later in this page can
make a lower-severity item outrank a higher one.

## 2. Score: severity × three adjustments

```
risk score = base(severity) × privilege × blast radius × confidence
```

| Adjustment | Rule | Why |
|---|---|---|
| Privilege | × 1.6 if any affected account is an administrator | The same gap on a super-admin is worse than on a contractor. |
| Blast radius | grows by 0.35 per tenfold increase in affected items, capped at × 2.0 | 40 affected accounts is worse than 4, but not ten times worse. |
| Confidence | reduced where the finding is inferred rather than read directly | An inference shouldn't outrank an observation. |

The score sets the order within a severity, and it's what the quarterly
comparison sums up as "total risk".

## 3. Action plan order

1. **Severity first**: every critical item, then high, then medium, then low.
2. **Within a severity, risk removed per hour**: `score ÷ estimated hours`, so
   the cheap, high-value fixes come first.
3. **Ties** break by number of affected items, then by finding ID, so the order
   never changes between two runs on the same data.

The plan lists **actions**, not findings. Findings fixed by the same action
become one entry ("also resolves …"), and findings about the same application
are shown under that application.

### Why severity comes first

The first version sorted by risk per hour alone. On the planted tenant, that put
a 30-minute medium ("no warning before external sharing") above two criticals
("an app can administer every account", "the donor list is public"), and left
"8 staff without 2SV" out of the top 10 entirely. The brief says that when the
manual review disagrees, the rubric is wrong. This is the fix.

## 4. Effort estimates

Hours per remediation, from `effort_hours` in the matrix file. They're
estimates: replace them with measured times once there's delivery data from
real engagements. Fixes done one account or one file at a time scale with the
number of items:

```
hours = min(base + per_item × items, cap)
```

| Remediation | Base | Per item | Cap |
|---|---|---|---|
| Restrict public links | 0.25 | 0.1 | 8 |
| Enforce 2SV for all users | 1.0 | 0.1 | 8 |
| Enforce 2SV for admins | 0.5 | 0.25 | 3 |
| Security keys for admins | 1.0 | 0.5 | 6 |
| Remove dormant admin rights | 0.5 | 0.25 | 3 |
| Suspend dormant accounts | 0.5 | 0.25 | 8 |
| Remove never-used accounts | 0.25 | 0.1 | 4 |
| Review suspended accounts | 0.5 | 0.1 | 4 |
| Revoke departed staff's app grants | 0.5 | 0.1 | 3 |
| Everything else | flat, 0.5–2 hours | – | – |

A flat estimate misranks. "Restrict public links" used to cost 3 hours whether
it was 3 files or 300, which pushed a critical, 30-minute fix down to 8th place.

## 5. Worked example

Planted tenant, GWS-MFA-002: "8 of 32 active accounts have no second factor".

1. Impact 4, exposure 4 → **High**.
2. Base score for High, × 1.0 privilege (no administrators among the 8),
   × the blast radius for 8 accounts, × 1.0 confidence (read directly from the
   directory) → **32.9**.
3. Effort: `min(1.0 + 0.1 × 8, 8)` = **1.8 hours**.
4. Risk per hour: 32.9 ÷ 1.8 = **18.3**. It comes after the four criticals and
   after the highs with more risk removed per hour. It's **#8**.

## 6. Finding IDs

A finding's ID is a hash of the rule, plus the application for rules that report
one finding per app. It doesn't include who's affected. So "8 accounts without
2SV" and, next quarter, "7 accounts without 2SV" are the same finding, and the
quarterly comparison reports it as **improved: 8 → 7 (pat.dunne fixed)**
instead of "1 resolved, 1 new". Severity, score, counts, dates and display
names are never part of the ID either.

## 7. Changing the rubric

Edit `config/risk_matrix.yaml`, bump its `version`, and re-review the top 10.
`tests/risk/test_action_plan.py` pins the reviewed order for the planted tenant,
so any change that moves it fails the test until it has been looked at again.
