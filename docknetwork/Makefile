all:
	echo "test,setup,create_proof,verify,proof_size" > stats_dock.csv
	STATS_FILE=stats_dock.csv cargo test --release

clean:
	rm stats*
	rm -rf target
