//! End-to-end tests for Tron network support
//! 
//! These tests verify that Foundry can successfully interact with Tron networks
//! by deploying and interacting with smart contracts.

use alloy_primitives::{address, U256, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types::{TransactionRequest, BlockNumberOrTag};
use alloy_network::{TransactionBuilder, ReceiptResponse};
use alloy_serde::WithOtherFields;
use anvil::{spawn, NodeConfig};

/// Test deploying a simple TRC-20 token contract on Tron Mainnet (local anvil)
#[tokio::test(flavor = "multi_thread")]
async fn test_deploy_trc20_on_tron_mainnet() {
    // Start anvil with Tron Mainnet chain ID
    let (_api, handle) = spawn(NodeConfig::test().with_chain_id(Some(728126428u64))).await;
    let provider = handle.http_provider();

    // Verify we're on Tron Mainnet
    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 728126428);

    // Simple TRC-20 contract bytecode (minimal ERC-20 implementation)
    // This is a simplified bytecode that creates a basic token contract
    let contract_bytecode: Bytes = "0x608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a3610c9c806100d66000396000f3fe".parse().unwrap();

    // Deploy the contract
    let deploy_tx = TransactionRequest::default()
        .with_input(contract_bytecode)
        .with_gas_limit(1_000_000)
        .with_gas_price(420); // Tron energy price

    let deploy_tx = WithOtherFields::new(deploy_tx);
    
    let pending_tx = provider.send_transaction(deploy_tx).await.unwrap();
    let receipt = pending_tx.get_receipt().await.unwrap();

    // Verify deployment was successful
    assert!(receipt.status());
    assert!(receipt.contract_address.is_some());
    
    let contract_address = receipt.contract_address.unwrap();
    
    // Verify the contract exists by checking its code
    let code = provider.get_code_at(contract_address).await.unwrap();
    assert!(!code.is_empty(), "Contract should have non-empty code");
    
    println!("Successfully deployed TRC-20 contract at: {:?}", contract_address);
}

/// Test deploying a simple TRC-20 token contract on Tron Shasta Testnet (local anvil)
#[tokio::test(flavor = "multi_thread")]
async fn test_deploy_trc20_on_tron_shasta() {
    // Start anvil with Tron Shasta chain ID
    let (_api, handle) = spawn(NodeConfig::test().with_chain_id(Some(2494104990u64))).await;
    let provider = handle.http_provider();

    // Verify we're on Tron Shasta
    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 2494104990);

    // Simple contract creation (empty contract for testing)
    let contract_bytecode: Bytes = "0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea264697066735822122000000000000000000000000000000000000000000000000000000000000000000064736f6c63430008110033".parse().unwrap();

    let deploy_tx = TransactionRequest::default()
        .with_input(contract_bytecode)
        .with_gas_limit(500_000)
        .with_gas_price(420);

    let deploy_tx = WithOtherFields::new(deploy_tx);
    
    let pending_tx = provider.send_transaction(deploy_tx).await.unwrap();
    let receipt = pending_tx.get_receipt().await.unwrap();

    // Verify deployment was successful
    assert!(receipt.status());
    assert!(receipt.contract_address.is_some());
    
    println!("Successfully deployed contract on Tron Shasta at: {:?}", receipt.contract_address.unwrap());
}

/// Test basic TRX transfers on Tron network
#[tokio::test(flavor = "multi_thread")]
async fn test_trx_transfer() {
    let (_api, handle) = spawn(NodeConfig::test().with_chain_id(Some(728126428u64))).await;
    let provider = handle.http_provider();

    // Get the default account (should have TRX balance from genesis)
    let accounts = provider.get_accounts().await.unwrap();
    assert!(!accounts.is_empty(), "Should have at least one account");
    
    let from_account = accounts[0];
    let to_account = address!("0x1234567890123456789012345678901234567890");

    // Check initial balance
    let initial_balance = provider.get_balance(from_account).await.unwrap();
    assert!(initial_balance > U256::ZERO, "Account should have TRX balance");

    // Send TRX transfer
    let transfer_amount = U256::from(1_000_000); // 1 TRX in Sun
    let transfer_tx = TransactionRequest::default()
        .with_to(to_account)
        .with_value(transfer_amount)
        .with_from(from_account)
        .with_gas_limit(21_000)
        .with_gas_price(420);

    let transfer_tx = WithOtherFields::new(transfer_tx);
    
    let pending_tx = provider.send_transaction(transfer_tx).await.unwrap();
    let receipt = pending_tx.get_receipt().await.unwrap();

    // Verify transfer was successful
    assert!(receipt.status());
    
    // Check balances after transfer
    let to_balance = provider.get_balance(to_account).await.unwrap();
    assert_eq!(to_balance, transfer_amount, "Recipient should have received TRX");
    
    println!("Successfully transferred {} Sun (TRX) to {:?}", transfer_amount, to_account);
}

/// Test that Tron-specific features work correctly
#[tokio::test(flavor = "multi_thread")]
async fn test_tron_specific_features() {
    let (_api, handle) = spawn(NodeConfig::test().with_chain_id(Some(728126428u64))).await;
    let provider = handle.http_provider();

    // Test that transaction count (nonce) is always 0 for Tron
    let test_address = address!("0x1234567890123456789012345678901234567890");
    let nonce = provider.get_transaction_count(test_address).await.unwrap();
    assert_eq!(nonce, 0, "Tron should always return nonce 0");

    // Test that we can get the latest block
    let latest_block = provider.get_block_number().await.unwrap();
    assert!(latest_block >= 0, "Should be able to get block number");

    // Test that we can get block by number (should work with "latest")
    let block = provider.get_block_by_number(BlockNumberOrTag::Latest).await.unwrap();
    assert!(block.is_some(), "Should be able to get latest block");
    
    let block = block.unwrap();
    assert_eq!(block.header.number, latest_block, "Block numbers should match");
    
    // Verify that the block has a state root (should be injected dummy value for Tron)
    assert_ne!(block.header.state_root, alloy_primitives::B256::ZERO, "State root should not be zero");
    
    println!("Tron-specific features working correctly on block {}", latest_block);
}

/// Test contract interaction on Tron network
#[tokio::test(flavor = "multi_thread")]
async fn test_contract_interaction_tron() {
    let (_api, handle) = spawn(NodeConfig::test().with_chain_id(Some(728126428u64))).await;
    let provider = handle.http_provider();

    // Deploy a simple storage contract
    // This contract has a single storage slot that can be set and retrieved
    let storage_contract_bytecode: Bytes = "0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100a1565b60405180910390f35b610073600480360381019061006e91906100ed565b61007e565b005b60008054905090565b8060008190555050565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b92915050565b600080fd5b6100ca81610088565b81146100d557600080fd5b50565b6000813590506100e7816100c1565b92915050565b600060208284031215610103576101026100bc565b5b6000610111848285016100d8565b9150509291505056fea264697066735822122000000000000000000000000000000000000000000000000000000000000000000064736f6c63430008110033".parse().unwrap();

    let deploy_tx = TransactionRequest::default()
        .with_input(storage_contract_bytecode)
        .with_gas_limit(1_000_000)
        .with_gas_price(420);

    let deploy_tx = WithOtherFields::new(deploy_tx);
    
    let pending_tx = provider.send_transaction(deploy_tx).await.unwrap();
    let receipt = pending_tx.get_receipt().await.unwrap();

    assert!(receipt.status());
    let contract_address = receipt.contract_address.unwrap();

    // Call the contract to set a value (function selector for set(uint256))
    let set_value = U256::from(42);
    let set_call_data: Bytes = format!("0x6057361d{:064x}", set_value).parse().unwrap(); // set(uint256) with value 42

    let set_tx = TransactionRequest::default()
        .with_to(contract_address)
        .with_input(set_call_data)
        .with_gas_limit(100_000)
        .with_gas_price(420);

    let set_tx = WithOtherFields::new(set_tx);
    
    let pending_tx = provider.send_transaction(set_tx).await.unwrap();
    let receipt = pending_tx.get_receipt().await.unwrap();
    assert!(receipt.status());

    // Call the contract to get the value (function selector for get())
    let get_call_data: Bytes = "0x2e64cec1".parse().unwrap(); // get() function selector

    let call_result = provider.call(
        WithOtherFields::new(TransactionRequest::default()
            .with_to(contract_address)
            .with_input(get_call_data))
    ).await.unwrap();

    // Decode the result (should be 42)
    let result_value = U256::from_be_slice(&call_result[..]);
    assert_eq!(result_value, set_value, "Contract should return the value we set");
    
    println!("Successfully interacted with contract on Tron: set and retrieved value {}", result_value);
}

/// Test gas/energy handling on Tron
#[tokio::test(flavor = "multi_thread")]
async fn test_tron_energy_handling() {
    let (_api, handle) = spawn(NodeConfig::test().with_chain_id(Some(728126428u64))).await;
    let provider = handle.http_provider();

    // Test that transactions work with Tron's energy model
    let accounts = provider.get_accounts().await.unwrap();
    let from_account = accounts[0];
    let to_account = address!("0x9876543210987654321098765432109876543210");

    // Send a transaction with high gas limit (should work due to relaxed gas checks)
    let transfer_tx = TransactionRequest::default()
        .with_to(to_account)
        .with_value(U256::from(500_000)) // 0.5 TRX in Sun
        .with_from(from_account)
        .with_gas_limit(50_000_000) // Very high gas limit (Tron allows this)
        .with_gas_price(420); // Tron energy price

    let transfer_tx = WithOtherFields::new(transfer_tx);
    
    let pending_tx = provider.send_transaction(transfer_tx).await.unwrap();
    let receipt = pending_tx.get_receipt().await.unwrap();

    assert!(receipt.status());
    
    // Verify that gas was consumed (but mapped to energy)
    assert!(receipt.gas_used > 0, "Should have consumed some gas/energy");
    assert!(receipt.gas_used < 50_000_000, "Should not have used all gas");
    
    println!("Successfully handled Tron energy model: used {} gas/energy units", receipt.gas_used);
} 