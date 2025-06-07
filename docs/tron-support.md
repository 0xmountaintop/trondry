# Tron Network Support in Foundry

This document provides comprehensive guidance for using Foundry with Tron networks, including Tron Mainnet and Shasta Testnet.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Network Configuration](#network-configuration)
- [Key Differences from Ethereum](#key-differences-from-ethereum)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [API Reference](#api-reference)

## Overview

Foundry's Tron support enables developers to:

- Deploy and interact with smart contracts on Tron networks
- Use existing Solidity contracts without modification (TVM is EVM-compatible)
- Develop and test TRC-20 tokens and DeFi protocols
- Leverage Foundry's testing framework for Tron contracts
- Use local development environments with `anvil`

### Supported Networks

| Network | Chain ID | RPC URL | Explorer |
|---------|----------|---------|----------|
| Tron Mainnet | 728126428 | https://api.trongrid.io | https://tronscan.org |
| Tron Shasta Testnet | 2494104990 | https://api.shasta.trongrid.io | https://shasta.tronscan.org |

## Quick Start

### 1. Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### 2. Initialize a New Project

```bash
forge init my-tron-project
cd my-tron-project
```

### 3. Configure for Tron

Create or update `foundry.toml`:

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]

[rpc_endpoints]
tron_mainnet = "https://api.trongrid.io"
tron_shasta = "https://api.shasta.trongrid.io"

[profile.tron]
chain_id = 728126428
gas_price = 420
gas_limit = 50000000

[profile.tron_shasta]
chain_id = 2494104990
gas_price = 420
gas_limit = 50000000
```

### 4. Deploy Your First Contract

```bash
# Deploy to Tron Shasta Testnet
forge create src/Counter.sol:Counter \
  --rpc-url tron_shasta \
  --private-key $PRIVATE_KEY
```

## Network Configuration

### Environment Variables

Set up your environment for Tron development:

```bash
# Tron Shasta Testnet (for testing)
export TRON_SHASTA_RPC_URL="https://api.shasta.trongrid.io"
export TRON_SHASTA_PRIVATE_KEY="your_private_key_here"

# Tron Mainnet (for production)
export TRON_MAINNET_RPC_URL="https://api.trongrid.io"
export TRON_MAINNET_PRIVATE_KEY="your_private_key_here"
```

### Using TronGrid API Keys

For production applications, obtain an API key from [TronGrid](https://www.trongrid.io/):

```bash
# With API key
export TRON_RPC_URL="https://api.trongrid.io/your-api-key"
```

### Local Development with Anvil

Start a local Tron development node:

```bash
# Tron Mainnet simulation
anvil --chain-id 728126428 --gas-price 420 --gas-limit 50000000

# Tron Shasta simulation
anvil --chain-id 2494104990 --gas-price 420 --gas-limit 50000000

# With pre-funded accounts (TRX in Sun)
anvil --chain-id 728126428 --balance 10000000000  # 10,000 TRX
```

## Key Differences from Ethereum

### 1. Energy vs Gas

Tron uses "Energy" instead of gas:

- **Gas Price**: Set to Tron's energy price (typically 420 Sun)
- **Gas Limit**: Higher limits are common (50M+ units)
- **Conversion**: Foundry handles gas↔energy conversion automatically (1:1 mapping)

### 2. Currency Units

- **TRX**: Base currency (like ETH)
- **Sun**: Smallest unit (1 TRX = 1,000,000 Sun, like Wei)
- **Balances**: Displayed in Sun when using `cast balance`

### 3. Account Nonces

- **Tron**: No account nonces - transactions don't require sequential ordering
- **Foundry**: Always returns nonce 0 for Tron addresses

### 4. Address Format

- **Standard**: 20-byte hex addresses (0x...)
- **Tron Prefix**: Some addresses may have 0x41 prefix (handled automatically)
- **Base58**: Tron also uses Base58 addresses (not supported in Foundry)

### 5. Block Structure

- **State Root**: May be missing in Tron blocks (Foundry injects dummy values)
- **Block Tags**: Historical queries limited to "latest" on some nodes

## Usage Examples

### TRC-20 Token Development

#### 1. Create a TRC-20 Token

```solidity
// src/MyToken.sol
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MyToken is ERC20 {
    constructor(
        string memory name,
        string memory symbol,
        uint256 totalSupply
    ) ERC20(name, symbol) {
        _mint(msg.sender, totalSupply);
    }
}
```

#### 2. Deploy the Token

```bash
# Deploy to Tron Shasta
forge create src/MyToken.sol:MyToken \
  --rpc-url $TRON_SHASTA_RPC_URL \
  --private-key $TRON_SHASTA_PRIVATE_KEY \
  --constructor-args "My Token" "MTK" 1000000000000000000000000
```

#### 3. Interact with the Token

```bash
# Get token details
cast call $TOKEN_ADDRESS "name()" --rpc-url $TRON_SHASTA_RPC_URL
cast call $TOKEN_ADDRESS "symbol()" --rpc-url $TRON_SHASTA_RPC_URL
cast call $TOKEN_ADDRESS "totalSupply()" --rpc-url $TRON_SHASTA_RPC_URL

# Check balance
cast call $TOKEN_ADDRESS "balanceOf(address)" $YOUR_ADDRESS --rpc-url $TRON_SHASTA_RPC_URL

# Transfer tokens
cast send $TOKEN_ADDRESS "transfer(address,uint256)" $RECIPIENT_ADDRESS 1000000000000000000 \
  --rpc-url $TRON_SHASTA_RPC_URL \
  --private-key $TRON_SHASTA_PRIVATE_KEY
```

### Testing Tron Contracts

#### 1. Write Tests

```solidity
// test/MyToken.t.sol
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/MyToken.sol";

contract MyTokenTest is Test {
    MyToken token;
    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        token = new MyToken("Test Token", "TEST", 1000000 * 10**18);
    }

    function testInitialSupply() public {
        assertEq(token.totalSupply(), 1000000 * 10**18);
        assertEq(token.balanceOf(address(this)), 1000000 * 10**18);
    }

    function testTransfer() public {
        uint256 amount = 1000 * 10**18;
        token.transfer(alice, amount);
        assertEq(token.balanceOf(alice), amount);
    }

    function testTronChainId() public {
        // Test with Tron chain ID
        vm.chainId(728126428);
        assertTrue(block.chainid == 728126428);
    }
}
```

#### 2. Run Tests

```bash
# Run tests locally
forge test

# Run tests with Tron chain ID
forge test --chain-id 728126428

# Run specific test
forge test --match-test testTronChainId
```

### DeFi Protocol Development

#### 1. Simple DEX Contract

```solidity
// src/SimpleDEX.sol
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SimpleDEX is ReentrancyGuard {
    mapping(address => uint256) public trxBalance;
    mapping(address => mapping(address => uint256)) public tokenBalance;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(address indexed user, address indexed token, uint256 amount);
    event Trade(address indexed user, address tokenA, address tokenB, uint256 amountA, uint256 amountB);

    function depositTRX() external payable {
        require(msg.value > 0, "Amount must be greater than 0");
        trxBalance[msg.sender] += msg.value;
        emit Deposit(msg.sender, address(0), msg.value);
    }

    function depositToken(address token, uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        tokenBalance[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    function withdrawTRX(uint256 amount) external nonReentrant {
        require(trxBalance[msg.sender] >= amount, "Insufficient balance");
        trxBalance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, address(0), amount);
    }

    function withdrawToken(address token, uint256 amount) external {
        require(tokenBalance[msg.sender][token] >= amount, "Insufficient balance");
        tokenBalance[msg.sender][token] -= amount;
        IERC20(token).transfer(msg.sender, amount);
        emit Withdrawal(msg.sender, token, amount);
    }
}
```

#### 2. Deploy and Test

```bash
# Deploy DEX
forge create src/SimpleDEX.sol:SimpleDEX \
  --rpc-url $TRON_SHASTA_RPC_URL \
  --private-key $TRON_SHASTA_PRIVATE_KEY

# Deposit TRX (1 TRX = 1,000,000 Sun)
cast send $DEX_ADDRESS "depositTRX()" \
  --value 1000000 \
  --rpc-url $TRON_SHASTA_RPC_URL \
  --private-key $TRON_SHASTA_PRIVATE_KEY

# Check TRX balance
cast call $DEX_ADDRESS "trxBalance(address)" $YOUR_ADDRESS \
  --rpc-url $TRON_SHASTA_RPC_URL
```

## Best Practices

### 1. Gas/Energy Management

```bash
# Use appropriate gas settings for Tron
forge create MyContract \
  --gas-price 420 \
  --gas-limit 50000000 \
  --rpc-url $TRON_RPC_URL
```

### 2. Testing Strategy

```solidity
// Use Tron-specific test configurations
contract TronTest is Test {
    function setUp() public {
        // Set Tron chain ID for tests
        vm.chainId(728126428);
        
        // Use realistic gas prices
        vm.txGasPrice(420);
    }
}
```

### 3. Error Handling

```solidity
// Handle Tron-specific conditions
contract TronContract {
    modifier onlyTron() {
        require(
            block.chainid == 728126428 || block.chainid == 2494104990,
            "Only supported on Tron networks"
        );
        _;
    }
}
```

### 4. Address Validation

```solidity
// Validate addresses for Tron
function isValidTronAddress(address addr) internal pure returns (bool) {
    // Basic validation - non-zero address
    return addr != address(0);
}
```

## Troubleshooting

### Common Issues

#### 1. "nonce too low" Error

**Problem**: Tron doesn't use nonces, but some tools expect them.

**Solution**: This is expected behavior. The transaction will still process correctly.

#### 2. "Insufficient funds for gas * price + value"

**Problem**: Account doesn't have enough TRX for transaction fees.

**Solutions**:
- Get TRX from [Tron Shasta Faucet](https://www.trongrid.io/shasta) for testnet
- Reduce gas limit or gas price
- Check balance: `cast balance $ADDRESS --rpc-url $TRON_RPC_URL`

#### 3. "Block not found" or Historical Query Errors

**Problem**: Tron nodes may not support historical block queries.

**Solution**: Use "latest" block tag or work with recent blocks only.

#### 4. RPC Connection Issues

**Problem**: Connection timeouts or rate limiting.

**Solutions**:
- Use TronGrid API key for higher rate limits
- Implement retry logic in scripts
- Use multiple RPC endpoints for redundancy

### Debugging Tips

#### 1. Enable Verbose Logging

```bash
# Enable detailed logging
export RUST_LOG=foundry=debug
forge create MyContract --rpc-url $TRON_RPC_URL
```

#### 2. Test Locally First

```bash
# Test with local anvil before deploying
anvil --chain-id 728126428 &
forge create MyContract --rpc-url http://localhost:8545
```

#### 3. Verify Contract Deployment

```bash
# Check if contract was deployed
cast code $CONTRACT_ADDRESS --rpc-url $TRON_RPC_URL

# Get transaction receipt
cast receipt $TX_HASH --rpc-url $TRON_RPC_URL
```

## Limitations

### Current Limitations

1. **Forking**: Limited historical state forking due to Tron's architecture
2. **Debugging**: Advanced debugging features work best with local `anvil`
3. **RPC Methods**: Some Ethereum-specific RPC methods unavailable
4. **Address Formats**: Base58 Tron addresses not supported (use hex format)
5. **Block History**: Limited access to historical blocks on some nodes

### Workarounds

1. **Use Local Development**: Test with `anvil` for full debugging capabilities
2. **Recent State Only**: Work with recent blocks and "latest" state
3. **Multiple RPC Providers**: Use different providers for redundancy
4. **Hex Addresses**: Always use hex format addresses in Foundry

## API Reference

### Tron-Specific Configuration Options

```toml
[profile.tron]
chain_id = 728126428          # Tron Mainnet
gas_price = 420               # Energy price in Sun
gas_limit = 50000000          # Higher limit for Tron
base_fee = 0                  # Tron doesn't use base fee
```

### Environment Variables

- `FOUNDRY_CHAIN_ID`: Set to Tron chain ID
- `FOUNDRY_GAS_PRICE`: Set to Tron energy price
- `FOUNDRY_GAS_LIMIT`: Set appropriate gas limit
- `FOUNDRY_RPC_URL`: Tron RPC endpoint

### Cast Commands for Tron

```bash
# Balance in Sun (TRX * 1,000,000)
cast balance $ADDRESS --rpc-url $TRON_RPC_URL

# Send TRX (value in Sun)
cast send $TO_ADDRESS --value 1000000 --rpc-url $TRON_RPC_URL

# Call contract (same as Ethereum)
cast call $CONTRACT "method()" --rpc-url $TRON_RPC_URL

# Get chain ID
cast chain-id --rpc-url $TRON_RPC_URL
```

### Forge Commands for Tron

```bash
# Create contract
forge create Contract --rpc-url $TRON_RPC_URL

# Test with Tron chain ID
forge test --chain-id 728126428

# Script deployment
forge script DeployScript --rpc-url $TRON_RPC_URL --broadcast
```

## Resources

- [Tron Developer Documentation](https://developers.tron.network/)
- [TronGrid API](https://www.trongrid.io/)
- [Tron Shasta Faucet](https://www.trongrid.io/shasta)
- [TronScan Explorer](https://tronscan.org/)
- [Foundry Book](https://book.getfoundry.sh/)

## Support

For Tron-specific issues:
- [Foundry GitHub Issues](https://github.com/foundry-rs/foundry/issues)
- [Foundry Telegram](https://t.me/foundry_rs)
- [Tron Developer Community](https://developers.tron.network/docs/tron-grid-intro) 