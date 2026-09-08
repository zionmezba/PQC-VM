SHELL := /usr/bin/env bash
IMAGE := pqc-vm
RUN := docker run --rm -v "$(CURDIR)":/work -w /work $(IMAGE)

.PHONY: image shell payloads test quick run figures clean help

help:
	@echo "make image      build the container (liboqs + oqs-provider, pinned)"
	@echo "make payloads   generate data/ at exact sizes"
	@echo "make test       correctness tests for the hybrid construction"
	@echo "make quick      smoke run (small n) -- checks wiring, not a result"
	@echo "make run        full experiment set + figures -> results/"
	@echo "make shell      interactive shell in the container"

image:
	docker build -f .devcontainer/Dockerfile -t $(IMAGE) .

payloads: image
	$(RUN) scripts/gen_payloads.sh

test: image
	$(RUN) python -m pytest tests -q

quick: payloads
	$(RUN) python -m bench.run_all --quick

run: payloads
	$(RUN) python -m bench.run_all

figures:
	$(RUN) python -m bench.figures

shell:
	docker run --rm -it -v "$(CURDIR)":/work -w /work $(IMAGE) bash

clean:
	rm -rf out results
