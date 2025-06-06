//! Tron network compatibility layer for Foundry
//!
//! This module provides compatibility adapters to make Foundry work with Tron networks.
//! Key differences handled:
//! - Tron has no account nonces (always return 0)
//! - Tron blocks may have missing stateRoot (inject dummy value)
//! - Tron addresses use 0x41 prefix (normalize as needed)
//! - Some RPC methods are unsupported or limited
//! - Transaction broadcasting via JSON-RPC or gRPC

use alloy_primitives::{Address, B256, Bytes, TxHash};
use alloy_rpc_types::{BlockId, BlockNumberOrTag};

/// Tron chain IDs
pub const TRON_MAINNET_CHAIN_ID: u64 = 728126428;
pub const TRON_SHASTA_CHAIN_ID: u64 = 2494104990;

/// Check if a chain ID corresponds to a Tron network
pub fn is_tron_chain(chain_id: u64) -> bool {
    matches!(chain_id, TRON_MAINNET_CHAIN_ID | TRON_SHASTA_CHAIN_ID)
}

/// Transaction broadcast mode for Tron
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TronTxMode {
    /// Use JSON-RPC eth_sendRawTransaction with protobuf data
    JsonRpc,
    /// Use gRPC broadcastTransaction
    Grpc,
    /// Auto-detect: try JSON-RPC first, fallback to gRPC
    Auto,
}

impl Default for TronTxMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl std::str::FromStr for TronTxMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "jsonrpc" | "json-rpc" | "json_rpc" => Ok(Self::JsonRpc),
            "grpc" => Ok(Self::Grpc),
            "auto" => Ok(Self::Auto),
            _ => Err(format!("Invalid Tron transaction mode: {s}. Valid options: jsonrpc, grpc, auto")),
        }
    }
}

/// Tron compatibility adapter for RPC methods
pub struct TronAdapter;

impl TronAdapter {
    /// Get transaction count (nonce) for Tron - always returns 0 since Tron has no nonces
    pub fn get_transaction_count(
        _address: Address,
        _block_number: Option<BlockId>,
        chain_id: u64,
    ) -> Option<u64> {
        if is_tron_chain(chain_id) {
            Some(0) // Tron has no nonces
        } else {
            None // Not a Tron chain, use normal logic
        }
    }

    /// Inject dummy state root for Tron blocks if missing
    pub fn ensure_state_root(state_root: B256, chain_id: u64) -> B256 {
        if is_tron_chain(chain_id) && state_root == B256::ZERO {
            // Return a dummy state root for Tron
            B256::from([0x01; 32])
        } else {
            state_root
        }
    }

    /// Normalize block number tags for Tron (force to "latest" if unsupported)
    pub fn normalize_block_number(
        block_number: Option<BlockId>,
        chain_id: u64,
    ) -> Option<BlockId> {
        if is_tron_chain(chain_id) {
            match block_number {
                Some(BlockId::Number(BlockNumberOrTag::Number(_))) => {
                    // Tron may not support historical block queries, force to latest
                    Some(BlockId::Number(BlockNumberOrTag::Latest))
                }
                other => other,
            }
        } else {
            block_number
        }
    }

    /// Check if an address has the Tron 0x41 prefix
    pub fn has_tron_prefix(address: Address) -> bool {
        let bytes = address.as_slice();
        bytes.len() >= 1 && bytes[0] == 0x41
    }

    /// Strip Tron 0x41 prefix from address if present
    pub fn strip_tron_prefix(address: Address) -> Address {
        let bytes = address.as_slice();
        if bytes.len() >= 1 && bytes[0] == 0x41 {
            // Create new address without the 0x41 prefix
            let mut new_bytes = [0u8; 20];
            new_bytes[..19].copy_from_slice(&bytes[1..]);
            Address::from(new_bytes)
        } else {
            address
        }
    }

    /// Add Tron 0x41 prefix to address if needed
    pub fn add_tron_prefix(address: Address) -> Address {
        let bytes = address.as_slice();
        if bytes[0] != 0x41 {
            let mut new_bytes = [0u8; 20];
            new_bytes[0] = 0x41;
            new_bytes[1..].copy_from_slice(&bytes[..19]);
            Address::from(new_bytes)
        } else {
            address
        }
    }

    /// Handle Tron transaction broadcasting
    /// 
    /// This method attempts to broadcast a transaction to a Tron network using the specified mode.
    /// For now, this is a placeholder that simulates the broadcast and returns a dummy hash.
    /// In a real implementation, this would:
    /// 1. Convert the Ethereum-style transaction to Tron protobuf format
    /// 2. Broadcast via JSON-RPC eth_sendRawTransaction or gRPC broadcastTransaction
    /// 3. Return the actual transaction hash from the network
    pub async fn broadcast_transaction(
        tx_data: Bytes,
        chain_id: u64,
        mode: TronTxMode,
        _rpc_url: Option<&str>,
    ) -> Result<Option<TxHash>, String> {
        if !is_tron_chain(chain_id) {
            return Ok(None); // Not a Tron chain, use normal logic
        }

        // TODO: Implement actual Tron transaction broadcasting
        // This is a placeholder implementation
        match mode {
            TronTxMode::JsonRpc => {
                // TODO: Convert tx_data to Tron protobuf format
                // TODO: Call JSON-RPC eth_sendRawTransaction with protobuf data
                tracing::info!("Broadcasting Tron transaction via JSON-RPC (placeholder)");
            }
            TronTxMode::Grpc => {
                // TODO: Convert tx_data to Tron protobuf format  
                // TODO: Call gRPC broadcastTransaction
                tracing::info!("Broadcasting Tron transaction via gRPC (placeholder)");
            }
            TronTxMode::Auto => {
                // TODO: Try JSON-RPC first, fallback to gRPC
                tracing::info!("Broadcasting Tron transaction via auto-detect (placeholder)");
            }
        }

        // For now, generate a dummy transaction hash based on the input data
        // In a real implementation, this would be the hash returned by the Tron network
        let hash = alloy_primitives::keccak256(&tx_data);
        Ok(Some(TxHash::from(hash)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_is_tron_chain() {
        assert!(is_tron_chain(TRON_MAINNET_CHAIN_ID));
        assert!(is_tron_chain(TRON_SHASTA_CHAIN_ID));
        assert!(!is_tron_chain(1)); // Ethereum mainnet
        assert!(!is_tron_chain(31337)); // Anvil default
    }

    #[test]
    fn test_get_transaction_count() {
        let addr = address!("0x1234567890123456789012345678901234567890");
        
        // Tron chains should return 0
        assert_eq!(
            TronAdapter::get_transaction_count(addr, None, TRON_MAINNET_CHAIN_ID),
            Some(0)
        );
        assert_eq!(
            TronAdapter::get_transaction_count(addr, None, TRON_SHASTA_CHAIN_ID),
            Some(0)
        );
        
        // Non-Tron chains should return None (use normal logic)
        assert_eq!(
            TronAdapter::get_transaction_count(addr, None, 1),
            None
        );
    }

    #[test]
    fn test_ensure_state_root() {
        let zero_root = B256::ZERO;
        let dummy_root = B256::from([0x01; 32]);
        let existing_root = B256::from([0x42; 32]);

        // Tron chain with zero state root should get dummy
        assert_eq!(
            TronAdapter::ensure_state_root(zero_root, TRON_MAINNET_CHAIN_ID),
            dummy_root
        );

        // Tron chain with existing state root should keep it
        assert_eq!(
            TronAdapter::ensure_state_root(existing_root, TRON_MAINNET_CHAIN_ID),
            existing_root
        );

        // Non-Tron chain should keep original
        assert_eq!(
            TronAdapter::ensure_state_root(zero_root, 1),
            zero_root
        );
    }

    #[test]
    fn test_normalize_block_number() {
        // Tron chain with specific block number should be forced to latest
        let block_num = Some(BlockId::Number(BlockNumberOrTag::Number(12345)));
        let latest = Some(BlockId::Number(BlockNumberOrTag::Latest));
        
        assert_eq!(
            TronAdapter::normalize_block_number(block_num, TRON_MAINNET_CHAIN_ID),
            latest
        );

        // Non-Tron chain should keep original
        assert_eq!(
            TronAdapter::normalize_block_number(block_num, 1),
            block_num
        );

        // Latest should stay latest
        assert_eq!(
            TronAdapter::normalize_block_number(latest, TRON_MAINNET_CHAIN_ID),
            latest
        );
    }

    #[test]
    fn test_tron_tx_mode_from_str() {
        assert_eq!("jsonrpc".parse::<TronTxMode>().unwrap(), TronTxMode::JsonRpc);
        assert_eq!("json-rpc".parse::<TronTxMode>().unwrap(), TronTxMode::JsonRpc);
        assert_eq!("grpc".parse::<TronTxMode>().unwrap(), TronTxMode::Grpc);
        assert_eq!("auto".parse::<TronTxMode>().unwrap(), TronTxMode::Auto);
        
        assert!("invalid".parse::<TronTxMode>().is_err());
    }

    #[tokio::test]
    async fn test_broadcast_transaction() {
        let tx_data = Bytes::from(vec![1, 2, 3, 4]);
        
        // Test Tron chain
        let result = TronAdapter::broadcast_transaction(
            tx_data.clone(),
            TRON_MAINNET_CHAIN_ID,
            TronTxMode::Auto,
            None,
        ).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        
        // Test non-Tron chain
        let result = TronAdapter::broadcast_transaction(
            tx_data,
            1, // Ethereum mainnet
            TronTxMode::Auto,
            None,
        ).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
} 