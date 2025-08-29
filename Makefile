SHELL := /usr/bin/env bash

.PHONY: quickstart keys payloads run all clean

quickstart: keys payloads run
	@echo "\nDone. See results/metrics.csv and out/*.p7s"

keys:
	scripts/make_keys.sh

payloads:
	scripts/gen_payloads.sh

run:
	# base message
	scripts/collect_metrics.sh data/msg.txt
	# payload matrix
	scripts/collect_metrics.sh data/payload_10k.bin
	scripts/collect_metrics.sh data/payload_1m.bin
	# 50MB can be heavy in free tiers; uncomment if resources allow
	# scripts/collect_metrics.sh data/payload_50m.bin

clean:
	rm -rf out results
	mkdir -p out results