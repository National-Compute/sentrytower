# SentryTower: common tasks. Run `make help` for the list.
PYTHON ?= python3
VENV ?= .venv
IMAGE ?= sentrytower:0.1.1
REPO ?= .
OUT ?= $(HOME)/sentrytower-results
BIN := $(VENV)/bin

.DEFAULT_GOAL := help
.PHONY: help install lint format typecheck test test-fast golden docker docker-smoke audit doctor clean

help: ## Show the targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Create .venv and install SentryTower with its development tools (uv when present, else pip)
	@if command -v uv >/dev/null 2>&1; then \
		uv venv --quiet $(VENV) && uv pip install --quiet --python $(BIN)/python -e ".[dev]"; \
	else \
		$(PYTHON) -m venv $(VENV) && $(BIN)/pip install --quiet -e ".[dev]"; \
	fi

lint: ## Run ruff (lint and format check) and mypy
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests
	$(BIN)/mypy

format: ## Format the code
	$(BIN)/ruff check --fix src tests
	$(BIN)/ruff format src tests

typecheck: ## Run mypy
	$(BIN)/mypy

test: ## Run the whole test suite (fake models only; no key needed)
	$(BIN)/pytest

test-fast: ## Run the tests without the whole-run scenarios
	$(BIN)/pytest -m "not slow"

golden: ## Regenerate the golden request fixtures (only for a deliberate change of the model requests)
	$(BIN)/python tests/golden.py --write

docker: ## Build the container image
	docker build -f docker/Dockerfile -t $(IMAGE) .

docker-smoke: docker ## Run the image against a local fake endpoint (no key, no model)
	PYTHON=$(PYTHON) docker/smoke.sh $(IMAGE) $(CURDIR) $(OUT)

audit: ## Audit REPO=path with the container image (needs SENTRYTOWER_API_KEY); outputs in OUT
	@test -n "$$SENTRYTOWER_API_KEY" || (echo "set SENTRYTOWER_API_KEY" >&2; exit 3)
	@mkdir -p $(OUT)
	docker run --rm -e SENTRYTOWER_API_KEY --read-only --cap-drop ALL --security-opt no-new-privileges \
		--user $$(id -u):$$(id -g) --tmpfs /home/dev:uid=$$(id -u),gid=$$(id -g),size=4g --tmpfs /tmp:size=1g \
		-v $(abspath $(REPO)):/workspace/repo:ro -v $(OUT):/workspace/out \
		$(IMAGE) audit /workspace/repo --out /workspace/out

doctor: ## Check the local environment (Python, Node.js, Pi, ripgrep, fd, the key, the endpoint)
	$(BIN)/sentrytower doctor

clean: ## Remove the build and test files
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
