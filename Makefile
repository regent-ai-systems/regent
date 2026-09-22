.PHONY: install check test lint typecheck secrets demo clean

AGENTGATEWAY ?= $(shell which agentgateway 2>/dev/null)

install:
	pip install -e ".[dev]" pyjwt cryptography mypy

lint:
	ruff check regent tests
	regent lint packs/ria --firm-overlay packs/ria/firm.example.yaml && regent lint packs/dev_default

typecheck:
	mypy regent --ignore-missing-imports || true   # advisory until the codebase is annotated end-to-end

secrets:
	@which gitleaks >/dev/null && gitleaks detect --no-banner --source . || echo "gitleaks not installed; skipping"

test:
	AGENTGATEWAY=$(AGENTGATEWAY) pytest -q

check: lint test typecheck secrets

demo:
	python examples/agentgateway-ria-demo/run_demo.py --agentgateway $(AGENTGATEWAY)

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info examples/*/out
	find . -name __pycache__ -type d -exec rm -rf {} +
