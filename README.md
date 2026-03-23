# ReqCast Wallet Risk Scorer

A high-value tool registered on ReqCast that scores wallet addresses for risk signals on Base network.

## What it does

Input: any EVM wallet address
Output: risk score (0-100), risk level, flags, and on-chain evidence

## Scoring model

Six risk signals each with weighted contribution:

| Signal | Weight |
|--------|--------|
| Interacted with flagged contract | 35 |
| High transaction failure rate (>30%) | 20 |
| Large token concentration (>80% one token) | 15 |
| Low transaction diversity (<=2 unique contracts) | 10 |
| Very new wallet (<10 transactions) | 10 |
| No ETH balance (<0.0001 ETH) | 10 |

## Risk levels

- 0-19: clean
- 20-39: low risk
- 40-69: moderate risk
- 70-100: high risk

## Example response

```json
{
  "wallet": "0x...",
  "risk_score": 45,
  "risk_level": "moderate risk",
  "flags": ["high_transaction_failure_rate", "very_new_wallet"],
  "flags_count": 2,
  "evidence": {
    "tx_count": 8,
    "failed_tx_count": 3,
    "failure_rate": 0.375,
    "eth_balance": 0.0012,
    "unique_contracts_interacted": 4
  },
  "powered_by": "ReqCast x402"
}
```

## Deployment

1. Deploy this to Railway as a new service
2. Set BASESCAN_API_KEY environment variable
3. Get free Basescan API key at https://basescan.org/apis
4. Register the tool on ReqCast:

```bash
curl -X POST https://api.reqcast.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_address":  "0xYOUR_WALLET",
    "tool_name":       "wallet-risk",
    "price_per_call":  "0.10",
    "callback_url":    "https://YOUR_RAILWAY_URL/score",
    "timeout_seconds": 15
  }'
```

5. Agents call it at: POST https://api.reqcast.com/pay/wallet-risk

## Extending the flagged address list

Edit the FLAGGED_ADDRESSES set in main.py to add known scam contracts, rug pull deployers, and exploiter addresses. Sources:
- https://github.com/MyEtherWallet/ethereum-lists
- https://chainabuse.com
- https://cryptoscamdb.org
