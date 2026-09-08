SHELL := /usr/bin/env bash
IMAGE := pqc-vm
RUN := docker run --rm -v "$(CURDIR)":/work -w /work $(IMAGE)

.PHONY: image shell payloads test quick run substitute figures paper-figures clean help

help:
	@echo "make image      build the container (liboqs + oqs-provider, pinned)"
	@echo "make payloads   generate data/ at exact sizes"
	@echo "make test       correctness tests for the hybrid construction"
	@echo "make quick      smoke run (small n) -- checks wiring, not a result"
	@echo "make substitute substitution + mode-downgrade attacks only"
	@echo "make paper-figures  IEEE-format PDF figures from existing results/"
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

substitute: payloads
	$(RUN) python -m bench.substitute --message data/msg.txt --out results

figures:
	$(RUN) python -m bench.figures

paper-figures:
	$(RUN) python -m bench.paper_figures --results results --out results/figures

shell:
	docker run --rm -it -v "$(CURDIR)":/work -w /work $(IMAGE) bash

clean:
	rm -rf out results
