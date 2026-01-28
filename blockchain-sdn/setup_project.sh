#!/bin/bash

echo "🔧 Setting up Blockchain SDN Project..."

# Create necessary directories
mkdir -p contracts migrations build scripts

# Create package.json if it doesn't exist
if [ ! -f package.json ]; then
    cat > package.json << EOF
{
  "name": "blockchain-sdn",
  "version": "1.0.0",
  "description": "Blockchain-based SDN Security Framework",
  "scripts": {
    "blockchain": "npx ganache-cli -d -p 7545 -m 'myth like bonus scare over problem client lizard pioneer submit female collect'",
    "deploy": "truffle migrate --network development"
  },
  "devDependencies": {
    "ganache-cli": "^6.12.2",
    "web3": "^1.8.0"
  }
}
EOF
fi

# Create truffle-config.js
cat > truffle-config.js << EOF
module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*",
    }
  },
  compilers: {
    solc: {
      version: "0.8.0",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  }
};
EOF

# Create migration file
cat > migrations/2_deploy_contracts.js << EOF
const SDNSecurity = artifacts.require("SDNSecurity");

module.exports = function (deployer) {
  deployer.deploy(SDNSecurity);
};
EOF

echo "✅ Project setup complete!"
echo "📁 Project structure:"
find . -type f -name "*.js" -o -name "*.json" -o -name "*.sol" | sort