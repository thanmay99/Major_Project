#!/bin/bash

echo "🚀 Starting Local Blockchain..."

cd ~/blockchain-sdn

# Kill any existing processes
echo "🛑 Cleaning up previous instances..."
pkill -f ganache-cli 2>/dev/null || true
sleep 2

# Start ganache-cli using local installation
echo "🔥 Starting Ganache..."
npx ganache-cli \
  -d \
  -p 7545 \
  -m "myth like bonus scare over problem client lizard pioneer submit female collect" \
  --chainId 1337 \
  --networkId 1337 \
  --gasLimit 8000000 \
  --gasPrice 20000000000 > ganache.log 2>&1 &

GANACHE_PID=$!
echo $GANACHE_PID > ganache.pid

echo "⏳ Waiting for blockchain to start..."
sleep 8

# Check if it's running
echo "📋 Testing blockchain connection..."
if curl -s -X POST -H "Content-Type: application/json" \
   --data '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' \
   http://localhost:7545 > /dev/null 2>&1; then
    
    echo "✅ Blockchain is running on http://localhost:7545"
    echo "📝 PID: $GANACHE_PID (saved to ganache.pid)"
    
    # Get account information
    echo "💰 Available accounts:"
    curl -s -X POST -H "Content-Type: application/json" \
         --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' \
         http://localhost:7545 | python3 -c "
import json, sys
data = json.load(sys.stdin)
if 'result' in data:
    accounts = data['result']
    for i, account in enumerate(accounts[:3]):  # Show first 3 accounts
        print(f'   Account {i}: {account}')
    if len(accounts) > 3:
        print(f'   ... and {len(accounts) - 3} more accounts')
"
    
else
    echo "❌ Failed to start blockchain."
    echo "📄 Check ganache.log for details:"
    tail -20 ganache.log
    exit 1
fi

echo ""
echo "🎉 Blockchain ready! You can now deploy contracts."
echo "💡 Run: ./deploy_contracts.sh"