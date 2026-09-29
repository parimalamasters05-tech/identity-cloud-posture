# Editorial review: the cold-reader test

The week-4 "done when" has two halves. The PDF generating end to end is
checked by the tool and its tests. The other half needs a person: **a
non-technical reader correctly explains the top three risks, unaided.** This
page is how to run that test so it tells you something you can act on.

## Who to ask

Someone who would plausibly receive this report and has never worked in IT: a
trustee, a finance lead, an operations manager, a friend who runs a small
organization. **Not** a developer, and not anyone who has seen this project.
One reader is the minimum; two catches more.

## What to hand them

- The PDF only, printed in greyscale if you can, since that's how a board
  packet arrives.
- Don't explain anything first. Don't say what the tool does, what "two-step
  verification" means, or which pages matter.
- Set the cover's organization and assessor names first (`ICP_CLIENT_NAME` and
  `ICP_ASSESSOR` in `.env`). A cover reading "Client" and "Assessor" makes the
  reader think it's a template.

Say only this:

> "This is a report about how well an organization's email and files are
> protected. Take ten minutes with it, as if it had landed in your board pack.
> Then I'll ask you a few questions. There are no wrong answers. If something
> is confusing, that's the report's fault, and it's exactly what I need to hear."

Then leave them alone for ten minutes. Don't watch over their shoulder.

## The questions

Ask them in this order, without prompting, and write down their exact words.

1. **"In your own words, what are the three biggest problems this organization has?"**
2. **"For the first one: what could actually go wrong? Who would it affect?"**
3. **"If you were on the board, what would you ask the IT person to do first, and roughly how long would it take?"**
4. **"Was there any word, sentence or page where you got lost?"** Ask them to
   point to it on the page.
5. **"Is there anything you think the report is saying that you're not sure you believe?"**

## Scoring

Compare their answers to the report's own "three things that matter most"
(executive summary, page 2).

| Question | Pass | Fail |
|---|---|---|
| 1 | Names all three in their own words, in any order | Misses one, or repeats a heading back without being able to say what it means |
| 2 | Describes a real consequence ("someone could get into the admin account with just a stolen password") | "Something about security" |
| 3 | Picks the top action plan item, or another critical one, and gives a time within a factor of two | Can't find the action plan, or picks a low item |
| 4 | Nothing, or cosmetic points only | Any term they needed explained to follow a risk |
| 5 | Nothing | Any claim they doubt: a credibility problem, not a vocabulary one |

**The test passes when question 1 passes unaided.** Questions 2–5 tell you what
to rewrite.

## Turning answers into rewrites

For each failure, find the exact sentence that caused it, then fix it at the
source, not in the PDF:

| Where the confusing text came from | Where to fix it |
|---|---|
| Headline risk paragraphs (page 2) | `_WHAT` and `_FAMILY_FRAMING` in `src/icp/reporting/executive_summary.py` |
| "Why this matters", the fix steps, "How to check it worked" | `config/remediation.yaml` |
| Finding titles | The rule in `src/icp/rules/` |
| Evidence sentences | The `summary=` text in the rule |
| Cover and scope lists | `_scope_statement` in `src/icp/reporting/renderer.py` |
| Any other fixed text | The template in `src/icp/reporting/templates/partials/` |

If the reader stumbled on a word, add it to `DIRECTOR_ONLY` or `EVERYWHERE` in
`tests/reporting/test_plain_language.py` before fixing it, so it can't come back.

## Record

Copy this block for each reader and keep it with the project:

```
Date:                    Reader (role, not name):
Report snapshot:
Q1 their three risks:    1.
                         2.
                         3.
Q1 result:               pass / fail
Q2 consequence:
Q3 first action + time:
Q4 where they got lost:  (page, exact phrase)
Q5 doubts:
Rewrites made:           (file, what changed)
Re-test:                 same reader / new reader, date, result
```

Re-test after rewriting, ideally with a new reader, since the first one now
knows the answers.
