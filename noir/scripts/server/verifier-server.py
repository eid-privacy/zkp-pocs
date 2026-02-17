import os
import shutil
import subprocess
import tempfile
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse

VERIFY_SCRIPT = os.getenv("VERIFY_SCRIPT", "/app/noir/scripts/verify-proof.sh")
VERIFY_TIMEOUT = int(os.getenv("VERIFY_TIMEOUT", "180"))
DEFAULT_SCHEME = os.getenv("DEFAULT_SCHEME", "")
WORK_DIR = os.getenv("WORK_DIR", "/app/noir")

app = FastAPI(title="Noir Proof Verifier", version="1.0.0")

@app.post("/verify")
async def verify_proof(
    proof: UploadFile = File(..., description="The proof file to verify"),
    vk: UploadFile = File(..., description="The verification key file"),
    public_inputs: UploadFile = File(..., description="The public inputs file"),
    scheme: str = Form(DEFAULT_SCHEME, description="The proving scheme to use (optional)")):
    
    if not os.path.isfile(VERIFY_SCRIPT):
        raise HTTPException(status_code=500, detail="Verification script not found")
    
    if not os.access(VERIFY_SCRIPT, os.X_OK):
        raise HTTPException(status_code=500, detail="Verification script is not executable")
    
    tmpdir = tempfile.mkdtemp(dir=WORK_DIR)
    
    try:
        proof_path = os.path.join(tmpdir, "proof")
        vk_path = os.path.join(tmpdir, "vk")
        public_inputs_path = os.path.join(tmpdir, "public_inputs")
        
        with open(proof_path, "wb") as f:
            shutil.copyfileobj(proof.file, f)
        
        with open(vk_path, "wb") as f:
            shutil.copyfileobj(vk.file, f)
        
        with open(public_inputs_path, "wb") as f:
            shutil.copyfileobj(public_inputs.file, f)
        
        result = subprocess.run(
            [VERIFY_SCRIPT, proof_path, vk_path, public_inputs_path, scheme],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VERIFY_TIMEOUT
        )
        
        verified = "VERIFIED"
        
        if result.returncode != 0:
            verified = "FAILED"
        
        return JSONResponse(content={"verification": verified})
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Verification timed out")
    finally:
        shutil.rmtree(tmpdir)