# Developer entry points for the harness.
#
# Two conventions are deliberate:
#
# * every Python invocation goes through the project venv by explicit path, so a target can never
#   silently pick up a different interpreter (or a system package) and produce a "works on my
#   machine" result;
# * the signed scope record and the keypair live *outside* the repository
#   ($(SCOPE_DIR)). The authorisation artefact must not sit in the tree the agent can write to,
#   otherwise "signed scope" would only mean "a file the agent could rewrite along with the rest".

SHELL := /bin/bash

REPO_ROOT := $(CURDIR)
VENV      := $(REPO_ROOT)/.venv
PY        := $(VENV)/bin/python
# The console entry point declared in pyproject.toml ([project.scripts] harness = harness.cli:app).
HARNESS   := $(VENV)/bin/harness

# Authority material: outside the repo, outside `git add -A`, outside the agent's writing scope.
SCOPE_DIR         := $(HOME)/.config/security-agent-harness
SCOPE_PRIVATE_KEY := $(SCOPE_DIR)/scope_ed25519_private.pem
SCOPE_PUBLIC_KEY  := $(SCOPE_DIR)/scope_ed25519_public.pem
SCOPE_FILE        := $(REPO_ROOT)/tests/fixtures/scope/lab_scope.json
SCOPE_SIGNED      := $(SCOPE_DIR)/lab_scope.signed.json

LAB_COMPOSE := $(REPO_ROOT)/lab/docker-compose.yml

# Overridable run parameters: `make run SKILL=log_analysis OBJECTIVE="..."`.
SKILL     ?= port_scan
OBJECTIVE ?= enumerate the services on the authorised lab hosts and map observed versions to candidate CVEs
RUN       ?= $(REPO_ROOT)/runs/latest
# `make eval EVAL_ARGS="--dry-run"` renders the eval commands without executing a run.
EVAL_ARGS ?=

.DEFAULT_GOAL := help
.PHONY: help install test lint lab-up lab-down scope run replay eval doctor

help:
	@echo "make install    - install the package and dev dependencies into .venv"
	@echo "make test       - run the test suite with the project venv"
	@echo "make lint       - byte-compile and (when available) lint every first-party tree"
	@echo "make lab-up     - start the egress-isolated lab targets (no host ports published)"
	@echo "make lab-down   - stop the lab and remove its network"
	@echo "make scope      - create the scope keypair outside the repo and sign the lab scope record"
	@echo "make run        - run one investigation (SKILL= OBJECTIVE= RUN=)"
	@echo "make replay     - replay a recorded run (RUN=)"
	@echo "make eval       - execute every scenario and write the metrics table"
	@echo "make doctor     - check the local environment (model endpoint, lab, keys)"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest tests -q

lint:
	# Byte-compiling the first-party trees catches syntax and import-time typos without needing a
	# linter to be installed; ruff is used when the environment happens to provide it.
	$(PY) -m compileall -q src eval scripts tests
	@if $(PY) -c "import ruff" >/dev/null 2>&1; then $(PY) -m ruff check .; else echo "lint: ruff not installed, compileall only"; fi

lab-up:
	# `internal: true` means the targets have no route off the host. Nothing is published to the
	# host either, so a run must execute inside labnet (see lab/README.md).
	docker compose -f $(LAB_COMPOSE) up --build --detach

lab-down:
	docker compose -f $(LAB_COMPOSE) down --volumes --remove-orphans

scope:
	$(PY) -m scripts.gen_scope_keypair --skip-if-exists \
		--private-key $(SCOPE_PRIVATE_KEY) --public-key $(SCOPE_PUBLIC_KEY)
	$(PY) -m scripts.sign_lab_scope \
		--scope $(SCOPE_FILE) --private-key $(SCOPE_PRIVATE_KEY) \
		--public-key $(SCOPE_PUBLIC_KEY) --out $(SCOPE_SIGNED)

run:
	$(HARNESS) run --skill $(SKILL) --objective "$(OBJECTIVE)" \
		--scope $(SCOPE_SIGNED) --public-key $(SCOPE_PUBLIC_KEY) --out $(RUN)

replay:
	$(HARNESS) replay $(RUN)

eval:
	# The runner shells out to the CLI with an argv list (never a shell string) and can be pointed
	# at another entry point with EVAL_ARGS="--entrypoint /path/to/harness".
	# The signing key lives outside the repository, so the signed scope record is supplied here
	# rather than referenced from a scenario file.
	$(PY) -m eval.runner --repo-root $(REPO_ROOT) --scope $(SCOPE_SIGNED) \
		--public-key $(SCOPE_PUBLIC_KEY) $(EVAL_ARGS)

doctor:
	$(HARNESS) doctor
