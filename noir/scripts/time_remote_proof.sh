#!/bin/bash

docker compose up -d

cd noir

output_file="stats_remote_proof_times.csv"
echo "proof,duration_ms" > "$output_file"

total_time=0
num_circuits=0

now_ms() {
    if [ -r /proc/uptime ]; then
        awk '{printf("%.0f", $1 * 1000)}' /proc/uptime
    else
        python3 - <<'EOF'
import time
print(int(time.time() * 1000))
EOF
    fi
}

for circuit in c??_*; do
    echo "Proving circuit: $circuit"

    start_time=$(now_ms)
    curl -s -X POST "http://localhost:8000/prove" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "proof_name=$circuit" > /dev/null
    end_time=$(now_ms)

    elapsed=$((end_time - start_time))
    total_time=$((total_time + elapsed))
    num_circuits=$((num_circuits + 1))

    echo "Proof for $circuit completed in ${elapsed} ms"
    echo "$circuit,$elapsed" >> "$output_file"
done

if [ $num_circuits -gt 0 ]; then
    average=$((total_time / num_circuits))
    echo "Average proof time: $average ms"
    echo "AVERAGE,$average" >> "$output_file"
else
    echo "No circuits found to prove."
fi