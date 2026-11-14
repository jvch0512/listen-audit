build:
	chmod +x bin/listen-audit tests/test.sh

test:
	sh tests/test.sh

sample: build
	mkdir -p docs site
	./bin/listen-audit examples/web01.txt examples/db01.txt > docs/sample-output.txt; true
	./bin/listen-audit examples/web01.txt examples/db01.txt --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "listen-audit" "Audits the output of ss or netstat for risky listening services. AWK." "Synthetic ss and netstat listings from two invented hosts."
