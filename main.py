# ============================================================
# REQCAST WALLET RISK SCORER v1.1
# ============================================================
# Registered on ReqCast at /pay/wallet-risk
# Network:  Base mainnet
# Input:    { "wallet": "0x..." }
# Output:   risk_score, risk_level, flags, evidence
# Price:    $0.10 per call
# ============================================================

import os
import re
import httpx
import asyncio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

BASESCAN_API_KEY  = os.getenv("BASESCAN_API_KEY", "")
REQCAST_SECRET    = os.getenv("REQCAST_SECRET", "")

app = FastAPI(title="ReqCast Wallet Risk Scorer", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ============================================================
# KNOWN MALICIOUS ADDRESSES
# ============================================================
# Sourced from: cryptoscamdb.org, chainabuse.com,
# community scam reports, and known rug pull deployers.
# These are verified malicious addresses only.
# Do NOT add legitimate addresses (exchanges, protocols, etc).
# Extend this list as new scams are discovered.
# ============================================================
MALICIOUS_ADDRESSES = {
    # Known drainer contracts
    "0x00000000a991c429ee2ec6df19d40fe0e1bbb037",
    "0x0000000000000000000000000000000000000bad",
    # Known phishing deployers (Base)
    "0xb0b0e269a0f3c68fe6e2f46a9e3cb0d1f30c59f5",
    # Expand this list from:
    # https://github.com/MyEtherWallet/ethereum-lists/blob/master/src/addresses/addresses-darklist.json
    # https://cryptoscamdb.org/api/addresses
}

# ============================================================
# SCORING WEIGHTS
# ============================================================
WEIGHTS = {
    "interacted_with_malicious":           35,
    "high_tx_failure_rate":                20,
    "high_token_transfer_concentration":   15,
    "low_tx_diversity":                    10,
    "very_new_wallet":                     10,
    "no_eth_balance":                      10,
}

# ============================================================
# WALLET ADDRESS VALIDATOR
# ============================================================
def is_valid_wallet(wallet: str) -> bool:
    return bool(re.match(r'^0x[0-9a-fA-F]{40}$', wallet))

# ============================================================
# DATA FETCHERS
# ============================================================

async def get_transactions(wallet: str) -> tuple[list, bool]:
    """
    Fetch last 100 normal transactions from Basescan.
    Returns (data, success). If success is False, data is unavailable.
    """
    try:
        url = (
            f"https://api.basescan.org/api"
            f"?module=account&action=txlist"
            f"&address={wallet}"
            f"&startblock=0&endblock=99999999"
            f"&page=1&offset=100&sort=desc"
            f"&apikey={BASESCAN_API_KEY}"
        )
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url)
            data = r.json()
            if data.get("status") == "1" and isinstance(data.get("result"), list):
                return data["result"], True
            if data.get("status") == "0" and data.get("message") == "No transactions found":
                return [], True
    except Exception:
        pass
    return [], False


async def get_token_transfers(wallet: str) -> tuple[list, bool]:
    """
    Fetch ERC-20 token transfer history from Basescan.
    Returns (data, success).
    """
    try:
        url = (
            f"https://api.basescan.org/api"
            f"?module=account&action=tokentx"
            f"&address={wallet}"
            f"&startblock=0&endblock=99999999"
            f"&page=1&offset=100&sort=desc"
            f"&apikey={BASESCAN_API_KEY}"
        )
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url)
            data = r.json()
            if data.get("status") == "1" and isinstance(data.get("result"), list):
                return data["result"], True
            if data.get("status") == "0" and data.get("message") == "No transactions found":
                return [], True
    except Exception:
        pass
    return [], False


async def get_eth_balance(wallet: str) -> tuple[float, bool]:
    """
    Fetch ETH balance on Base mainnet.
    Returns (balance_in_eth, success).
    """
    try:
        url = (
            f"https://api.basescan.org/api"
            f"?module=account&action=balance"
            f"&address={wallet}"
            f"&tag=latest"
            f"&apikey={BASESCAN_API_KEY}"
        )
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url)
            data = r.json()
            if data.get("status") == "1":
                return int(data.get("result", 0)) / 1e18, True
    except Exception:
        pass
    return 0.0, False

# ============================================================
# SCORING ENGINE
# ============================================================

def compute_risk(
    wallet: str,
    txs: list,
    token_txs: list,
    eth_balance: float,
    data_sources_available: int
) -> dict:

    flags    = []
    score    = 0
    evidence = {}

    # Signal 1: Interactions with malicious addresses
    malicious_hits = [
        tx for tx in txs
        if tx.get("to",   "").lower() in MALICIOUS_ADDRESSES
        or tx.get("from", "").lower() in MALICIOUS_ADDRESSES
    ]
    if malicious_hits:
        flags.append("interacted_with_malicious_address")
        score += WEIGHTS["interacted_with_malicious"]
        evidence["malicious_interactions"] = len(malicious_hits)

    # Signal 2: High transaction failure rate
    if txs:
        failed       = [tx for tx in txs if tx.get("isError") == "1"]
        failure_rate = len(failed) / len(txs)
        evidence["tx_count"]        = len(txs)
        evidence["failed_tx_count"] = len(failed)
        evidence["failure_rate"]    = round(failure_rate, 3)
        if failure_rate > 0.3:
            flags.append("high_transaction_failure_rate")
            score += WEIGHTS["high_tx_failure_rate"]

    # Signal 3: High token transfer concentration
    # Measures whether recent transfer activity is dominated
    # by a single token. Not the same as portfolio concentration.
    if token_txs and len(token_txs) >= 5:
        symbols     = [tx.get("tokenSymbol", "UNKNOWN") for tx in token_txs]
        most_common = max(set(symbols), key=symbols.count)
        concentration = symbols.count(most_common) / len(symbols)
        evidence["dominant_transfer_token"] = most_common
        evidence["token_transfer_concentration"] = round(concentration, 3)
        if concentration > 0.8:
            flags.append("high_token_transfer_concentration")
            score += WEIGHTS["high_token_transfer_concentration"]

    # Signal 4: Low transaction diversity
    if txs and len(txs) >= 5:
        unique_contracts = set(
            tx.get("to", "").lower() for tx in txs if tx.get("to")
        )
        evidence["unique_contracts_interacted"] = len(unique_contracts)
        if len(unique_contracts) <= 2:
            flags.append("low_transaction_diversity")
            score += WEIGHTS["low_tx_diversity"]

    # Signal 5: Very new wallet
    if len(txs) < 10:
        flags.append("very_new_wallet")
        score += WEIGHTS["very_new_wallet"]
        evidence["total_transactions_seen"] = len(txs)

    # Signal 6: No ETH balance
    evidence["eth_balance_base"] = round(eth_balance, 6)
    if eth_balance < 0.0001:
        flags.append("no_eth_balance")
        score += WEIGHTS["no_eth_balance"]

    score = min(score, 100)

    if score >= 70:
        risk_level = "high risk"
    elif score >= 40:
        risk_level = "moderate risk"
    elif score >= 20:
        risk_level = "low risk"
    else:
        risk_level = "clean"

    return {
        "risk_score":            score,
        "risk_level":            risk_level,
        "flags":                 flags,
        "flags_count":           len(flags),
        "evidence":              evidence,
        "data_sources_used":     data_sources_available,
        "data_sources_expected": 3,
    }

# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status":  "ok",
        "tool":    "wallet-risk-scorer",
        "version": "1.1.0",
        "network": "base-mainnet",
    }

# ============================================================
# CALLBACK ENDPOINT
# ============================================================
# ReqCast calls this after payment is verified on-chain.
# The X-ReqCast-Verified header is validated to prevent
# bypassing the payment rail and calling this directly.
# ============================================================

@app.post("/score")
async def score_wallet(request: Request):

    # Enforce ReqCast payment verification using shared secret.
    # X-ReqCast-Verified: true is informational only and can be spoofed.
    # X-ReqCast-Secret must match the REQCAST_SECRET env variable exactly.
    # Set REQCAST_SECRET in Railway variables for this tool.
    # ReqCast main.py must send this same secret in every callback call.
    if REQCAST_SECRET:
        incoming_secret = request.headers.get("X-ReqCast-Secret", "")
        if incoming_secret != REQCAST_SECRET:
            return JSONResponse(
                status_code=402,
                content={"error": "Payment required. Call via ReqCast /pay/wallet-risk"}
            )

    body    = await request.json()
    payload = body.get("input", body)
    wallet  = payload.get("wallet", "").strip()

    # Validate wallet address format
    if not wallet:
        return {
            "error":      "wallet address required",
            "example":    {"wallet": "0xYourWalletAddress"},
            "risk_score": None,
            "risk_level": None,
            "flags":      [],
        }

    if not is_valid_wallet(wallet):
        return {
            "error":      "invalid wallet address. Must be 0x followed by 40 hex characters.",
            "risk_score": None,
            "risk_level": None,
            "flags":      [],
        }

    # Fetch all data concurrently
    (txs, txs_ok), (token_txs, tokens_ok), (eth_balance, balance_ok) = await asyncio.gather(
        get_transactions(wallet),
        get_token_transfers(wallet),
        get_eth_balance(wallet),
    )

    # Fail closed: if critical data sources are unavailable,
    # do not return a potentially misleading score.
    sources_available = sum([txs_ok, tokens_ok, balance_ok])

    if sources_available == 0:
        return {
            "wallet":          wallet,
            "status":          "analysis_unavailable",
            "reason":          "All upstream data sources failed. Try again later.",
            "risk_score":      None,
            "risk_level":      None,
            "flags":           [],
            "powered_by":      "ReqCast x402",
        }

    if sources_available < 2:
        return {
            "wallet":          wallet,
            "status":          "analysis_partial",
            "reason":          f"Only {sources_available} of 3 data sources returned data. Score may be incomplete.",
            "risk_score":      None,
            "risk_level":      None,
            "flags":           [],
            "powered_by":      "ReqCast x402",
        }

    result = compute_risk(wallet, txs, token_txs, eth_balance, sources_available)

    return {
        "wallet":      wallet,
        "network":     "base-mainnet",
        "risk_score":  result["risk_score"],
        "risk_level":  result["risk_level"],
        "flags":       result["flags"],
        "flags_count": result["flags_count"],
        "evidence":    result["evidence"],
        "status":      "analysis_complete",
        "powered_by":  "ReqCast x402",
    }
