from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from engine import analyze_migration

# Load the secrets from the .env file
load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")

# Connect to Supabase
supabase: Client = create_client(url, key)

# Create the FastAPI app
app = FastAPI(title="SafeMigrate API")

# CORS Middleware to allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

# This defines what data the user must send us
class MigrationRequest(BaseModel):
    sql_text: str
    is_pro: bool = True  # 🚀 LAUNCH MODE: Defaults to True so everyone gets Pro features for free!
                          # (Later, change this back to False to enable the paywall)

@app.post("/analyze")
def analyze_endpoint(request: MigrationRequest):
    # 1. Run the engine brain!
    warnings = analyze_migration(request.sql_text)
    
    # 2. Calculate a basic risk score (25 points per warning)
    risk_score = len(warnings) * 25
    
    # 3. Save the scan to the Supabase 'scans' table
    scan_response = supabase.table('scans').insert({
        "sql_text": request.sql_text,
        "risk_score": risk_score
    }).execute()
    
    # Get the ID of the scan we just created
    scan_id = scan_response.data[0]['id']
    
    # 4. Save the warnings to the Supabase 'warnings' table
    if warnings:
        warning_records = []
        for w in warnings:
            # LAUNCH MODE: Because is_pro is True, this will save the real safe_sql to the database.
            # (When paywall is active, it will save "[Upgrade to Pro]" if is_pro is False)
            safe_sql_to_save = w["safe_sql"] if request.is_pro else "[Upgrade to Pro]"
            
            warning_records.append({
                "scan_id": scan_id,
                "rule": w["rule"],
                "severity": w["severity"],
                "message": w["message"],
                "unsafe_sql": w["unsafe_sql"],
                "safe_sql": safe_sql_to_save
            })
        
        # Insert all warnings at once
        supabase.table('warnings').insert(warning_records).execute()
    
    # LAUNCH MODE: Because is_pro is True, this block is skipped, and users see the real fixes.
    # PAYWALL LOGIC (Activate later): Hide safe_sql in the API response if user is not Pro
    if not request.is_pro:
        for w in warnings:
            w["safe_sql"] = "[Upgrade to Pro to see the safe SQL fix]"
    
    # 5. Return the results to the user
    return {
        "scan_id": scan_id,
        "risk_score": risk_score,
        "warnings_count": len(warnings),
        "warnings": warnings
    }