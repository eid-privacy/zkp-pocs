all:
	echo "wp6_revocation" > stats.txt
	./scripts/1-create-keys.py
	./scripts/2-create-signed-credentials.py
	./scripts/3-create-provers.py
	./scripts/4-create-witness.sh
	./scripts/5-create-proof.sh
	cat proofs/proof | wc -c >> stats.txt
	paste -sd, stats.txt > stats.csv

repeated:
	rm -f stats_coll.csv
	for a in $$( seq 10 ); do \
	  $(MAKE) all; \
	  cat stats.csv >> stats_coll.csv; \
	done

clean:
	rm -rf credentials proofs stats*
	find c??_* -name target | xargs rm -rf
	find c??_* -name "Prover*toml" | xargs rm -rf
