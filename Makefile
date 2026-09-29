# Thin wrappers. Everything here is a one-liner you could type by hand; the
# point is that nobody has to remember which flags matter.

.DEFAULT_GOAL := help
.PHONY: help install test security lint verify demo image image-scan clean acceptance week1 preflight

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install with dev dependencies
	pip install -e ".[dev]"
	pre-commit install

test: ## Run the full suite
	pytest

security: ## Run only the controls that must never regress
	pytest -m security -v

verify: ## Static read-only verification (control #3 of three)
	python tools/verify_readonly.py

lint: ## ruff, mypy, bandit, pip-audit
	ruff check src tests tools
	ruff format --check src tests tools
	mypy
	bandit -c pyproject.toml -r src -ll
	pip-audit --strict

image: ## Build the Docker image
	docker build -t icp:local .

image-scan: image ## Build, then scan the image for known vulnerabilities
	@command -v trivy >/dev/null || { echo "trivy not installed: https://trivy.dev"; exit 1; }
	trivy image --severity HIGH,CRITICAL --ignore-unfixed icp:local

preflight: ## Check credentials and delegation against a real tenant
	docker compose run --rm preflight

demo: ## Offline end-to-end run in Docker, no credentials needed
	docker compose run --rm demo

clean: ## Remove caches and build artifacts. Leaves client data alone.
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist src/*.egg-info .coverage coverage.xml htmlcov

acceptance: ## The brief's weekly done-when criteria (weeks 2-3, offline)
	pytest -m acceptance -v --no-header -p no:cacheprovider

week1: ## Print the week 1 manual procedure (needs a real dev tenant)
	@echo "Week 1 cannot be verified offline. See docs/acceptance-week1.md"
	@echo
	@grep -E '^## Step|^\| [0-9] \|' docs/acceptance-week1.md | head -20
