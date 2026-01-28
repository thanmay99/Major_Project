#!/bin/bash

echo "📦 Deploying Smart Contracts..."

cd ~/blockchain-sdn

# Check if blockchain is running
echo "🔍 Checking blockchain connection..."
if ! curl -s -X POST -H "Content-Type: application/json" \
   --data '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' \
   http://localhost:7545 > /dev/null 2>&1; then
    echo "❌ Blockchain not running. Please start it first:"
    echo "   ./start_blockchain.sh"
    exit 1
fi

echo "🔨 Compiling contracts..."
truffle compile

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed"
    exit 1
fi

echo "🚀 Deploying to blockchain..."
truffle migrate --network development

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 CONTRACT DEPLOYMENT SUCCESSFUL!"
    echo ""
    echo "📋 Next steps:"
    echo "   1. Save the contract address from above"
    echo "   2. Update blockchain_enhanced_controller.py with the address"
    echo "   3. Run: ryu-manager blockchain_enhanced_controller.py"
    echo ""
    echo "💡 The contract ABI is in build/contracts/SDNSecurity.json"
else
    echo "❌ Deployment failed"
    exit 1
fi
