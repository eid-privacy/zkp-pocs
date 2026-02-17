import os
import subprocess
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
import json

PROOF_SCRIPT = os.getenv("PROOF_SCRIPT", "/app/noir/scripts/create-proof-remote.sh")
WITNESS_SCRIPT = os.getenv("WITNESS_SCRIPT", "/app/noir/scripts/5-create-witness.sh")
PROOF_TIMEOUT = int(os.getenv("PROOF_TIMEOUT", "360"))
WORK_DIR = os.getenv("WORK_DIR", "/app/noir")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8080/verify")
DEFAULT_SCHEME = os.getenv("DEFAULT_SCHEME", "")

app = FastAPI(title="Noir Proof Prover", version="1.0.0")

@app.post("/prove")
async def prove(
    proof_name: str = Form(..., description="The name of the circuit to prove"),
    scheme: str = Form(DEFAULT_SCHEME, description="The proving scheme to use (optional)")):
    
    proof_dir = os.path.join(WORK_DIR, proof_name)
    
    if not os.path.isdir(proof_dir):
        raise HTTPException(status_code=404, detail="Proof directory not found")
    
    if not os.path.isfile(PROOF_SCRIPT):
        raise HTTPException(status_code=500, detail="Proof script not found")
    
    if not os.access(PROOF_SCRIPT, os.X_OK):
        raise HTTPException(status_code=500, detail="Proof script is not executable")
    
    result_create_witness = subprocess.run(
        [WITNESS_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=PROOF_TIMEOUT
    )
    
    print(f"Witness script stdout: {result_create_witness.stdout}")
    print(f"Witness script stderr: {result_create_witness.stderr}")
    
    if result_create_witness.returncode != 0:
        raise HTTPException(status_code=400, detail=f"Witness generation failed")
    
    result = subprocess.run(
        [PROOF_SCRIPT, proof_name, VERIFIER_URL, scheme],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=PROOF_TIMEOUT
    )
    
    print(f"Proof script stdout: {result.stdout}")
    print(f"Proof script stderr: {result.stderr}")
    
    if result.returncode != 0:
        raise HTTPException(status_code=400, detail=f"Proof verification failed")
    
    return JSONResponse(content={"message": "Proof verified successfully"})