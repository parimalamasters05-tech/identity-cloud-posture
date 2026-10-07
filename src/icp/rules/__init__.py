"""Detection rules -- one module per check family.

Importing this package registers every rule. Rules are platform-agnostic by
construction: they read only the normalized tenant view, never provider JSON.
"""

# Imported for their registration side effects. Order is irrelevant.
from icp.rules import (  # noqa: F401
    admin_role_sprawl,
    external_sharing,
    logging_readiness,
    mfa_coverage,
    microsoft,
    oauth_grant_risk,
    service_account_privilege,
    stale_accounts,
)
from icp.rules.base import Rule, RuleContext, all_rules, register, rules_for
from icp.rules.engine import AssessmentResult, assess

__all__ = [
    "AssessmentResult",
    "Rule",
    "RuleContext",
    "all_rules",
    "assess",
    "register",
    "rules_for",
]
