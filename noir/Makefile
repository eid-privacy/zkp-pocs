all: setup-proof create-proof

create-proof:
	./scripts/5-create-witness.sh
	./scripts/6-create-proof.sh

setup-proof:
	./scripts/1-create-keys.py
	./scripts/2-create-signed-credentials.py
	./scripts/3-create-provers.py
	./scripts/4-compile-circuits.sh

repeated:
	rm -f stats_coll.csv
	for a in $$( seq 10 ); do \
	  $(MAKE) all; \
	  cat stats_noir.csv >> stats_coll.csv; \
	done

clean:
	rm -rf credentials proofs stats* eid/src/constants.nr
	find c??_* -name target | xargs rm -rf
	find c??_* -name "Prover*toml" | xargs rm -rf
