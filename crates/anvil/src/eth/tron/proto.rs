//! Pre-generated protobuf types for Tron
//!
//! This module contains hand-written protobuf types for Tron to avoid
//! requiring protoc at build time. These types are compatible with
//! the official Tron protobuf definitions.

#[cfg(feature = "tron")]
pub mod protocol {
    use prost::Message;

    /// Transaction definition
    #[derive(Clone, PartialEq, Message)]
    pub struct Transaction {
        #[prost(message, optional, tag = "1")]
        pub raw_data: Option<transaction::Raw>,
        #[prost(bytes = "vec", repeated, tag = "2")]
        pub signature: Vec<Vec<u8>>,
        #[prost(message, repeated, tag = "5")]
        pub ret: Vec<transaction::Result>,
    }

    pub mod transaction {
        use prost::Message;

        /// Raw transaction data
        #[derive(Clone, PartialEq, Message)]
        pub struct Raw {
            #[prost(bytes = "vec", tag = "1")]
            pub ref_block_bytes: Vec<u8>,
            #[prost(int64, tag = "3")]
            pub ref_block_num: i64,
            #[prost(bytes = "vec", tag = "4")]
            pub ref_block_hash: Vec<u8>,
            #[prost(int64, tag = "8")]
            pub expiration: i64,
            #[prost(message, repeated, tag = "9")]
            pub auths: Vec<super::Authority>,
            #[prost(bytes = "vec", tag = "10")]
            pub data: Vec<u8>,
            #[prost(message, repeated, tag = "11")]
            pub contract: Vec<Contract>,
            #[prost(bytes = "vec", tag = "12")]
            pub scripts: Vec<u8>,
            #[prost(int64, tag = "14")]
            pub timestamp: i64,
            #[prost(int64, tag = "18")]
            pub fee_limit: i64,
        }

        /// Contract within a transaction
        #[derive(Clone, PartialEq, Message)]
        pub struct Contract {
            #[prost(enumeration = "contract::ContractType", tag = "1")]
            pub r#type: i32,
            #[prost(message, optional, tag = "2")]
            pub parameter: Option<prost_types::Any>,
            #[prost(bytes = "vec", tag = "3")]
            pub provider: Vec<u8>,
            #[prost(bytes = "vec", tag = "4")]
            pub contract_name: Vec<u8>,
            #[prost(int32, tag = "5")]
            pub permission_id: i32,
        }

        pub mod contract {
            /// Contract types
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
            #[repr(i32)]
            pub enum ContractType {
                #[default]
                AccountCreateContract = 0,
                TransferContract = 1,
                TransferAssetContract = 2,
                VoteAssetContract = 3,
                VoteWitnessContract = 4,
                WitnessCreateContract = 5,
                AssetIssueContract = 6,
                WitnessUpdateContract = 8,
                ParticipateAssetIssueContract = 9,
                AccountUpdateContract = 10,
                FreezeBalanceContract = 11,
                UnfreezeBalanceContract = 12,
                WithdrawBalanceContract = 13,
                UnfreezeAssetContract = 14,
                UpdateAssetContract = 15,
                ProposalCreateContract = 16,
                ProposalApproveContract = 17,
                ProposalDeleteContract = 18,
                SetAccountIdContract = 19,
                CustomContract = 20,
                CreateSmartContract = 30,
                TriggerSmartContract = 31,
                GetContract = 32,
                UpdateSettingContract = 33,
                ExchangeCreateContract = 41,
                ExchangeInjectContract = 42,
                ExchangeWithdrawContract = 43,
                ExchangeTransactionContract = 44,
                UpdateEnergyLimitContract = 45,
                AccountPermissionUpdateContract = 46,
                ClearAbiContract = 48,
                UpdateBrokerageContract = 49,
                ShieldedTransferContract = 51,
                MarketSellAssetContract = 52,
                MarketCancelOrderContract = 53,
                FreezeBalanceV2Contract = 54,
                UnfreezeBalanceV2Contract = 55,
                WithdrawExpireUnfreezeContract = 56,
                DelegateResourceContract = 57,
                UnDelegateResourceContract = 58,
                CancelAllUnfreezeV2Contract = 59,
            }

            impl TryFrom<i32> for ContractType {
                type Error = ();

                fn try_from(value: i32) -> Result<Self, Self::Error> {
                    match value {
                        0 => Ok(ContractType::AccountCreateContract),
                        1 => Ok(ContractType::TransferContract),
                        2 => Ok(ContractType::TransferAssetContract),
                        3 => Ok(ContractType::VoteAssetContract),
                        4 => Ok(ContractType::VoteWitnessContract),
                        5 => Ok(ContractType::WitnessCreateContract),
                        6 => Ok(ContractType::AssetIssueContract),
                        8 => Ok(ContractType::WitnessUpdateContract),
                        9 => Ok(ContractType::ParticipateAssetIssueContract),
                        10 => Ok(ContractType::AccountUpdateContract),
                        11 => Ok(ContractType::FreezeBalanceContract),
                        12 => Ok(ContractType::UnfreezeBalanceContract),
                        13 => Ok(ContractType::WithdrawBalanceContract),
                        14 => Ok(ContractType::UnfreezeAssetContract),
                        15 => Ok(ContractType::UpdateAssetContract),
                        16 => Ok(ContractType::ProposalCreateContract),
                        17 => Ok(ContractType::ProposalApproveContract),
                        18 => Ok(ContractType::ProposalDeleteContract),
                        19 => Ok(ContractType::SetAccountIdContract),
                        20 => Ok(ContractType::CustomContract),
                        30 => Ok(ContractType::CreateSmartContract),
                        31 => Ok(ContractType::TriggerSmartContract),
                        32 => Ok(ContractType::GetContract),
                        33 => Ok(ContractType::UpdateSettingContract),
                        41 => Ok(ContractType::ExchangeCreateContract),
                        42 => Ok(ContractType::ExchangeInjectContract),
                        43 => Ok(ContractType::ExchangeWithdrawContract),
                        44 => Ok(ContractType::ExchangeTransactionContract),
                        45 => Ok(ContractType::UpdateEnergyLimitContract),
                        46 => Ok(ContractType::AccountPermissionUpdateContract),
                        48 => Ok(ContractType::ClearAbiContract),
                        49 => Ok(ContractType::UpdateBrokerageContract),
                        51 => Ok(ContractType::ShieldedTransferContract),
                        52 => Ok(ContractType::MarketSellAssetContract),
                        53 => Ok(ContractType::MarketCancelOrderContract),
                        54 => Ok(ContractType::FreezeBalanceV2Contract),
                        55 => Ok(ContractType::UnfreezeBalanceV2Contract),
                        56 => Ok(ContractType::WithdrawExpireUnfreezeContract),
                        57 => Ok(ContractType::DelegateResourceContract),
                        58 => Ok(ContractType::UnDelegateResourceContract),
                        59 => Ok(ContractType::CancelAllUnfreezeV2Contract),
                        _ => Err(()),
                    }
                }
            }

            impl From<ContractType> for i32 {
                fn from(value: ContractType) -> Self {
                    value as i32
                }
            }
        }

        /// Transaction result
        #[derive(Clone, PartialEq, Message)]
        pub struct Result {
            #[prost(int64, tag = "1")]
            pub fee: i64,
            #[prost(enumeration = "result::Code", tag = "2")]
            pub ret: i32,
            #[prost(enumeration = "result::ContractResult", tag = "3")]
            pub contract_ret: i32,
            #[prost(string, tag = "14")]
            pub asset_issue_id: String,
            #[prost(int64, tag = "15")]
            pub withdraw_amount: i64,
            #[prost(int64, tag = "16")]
            pub unfreeze_amount: i64,
            #[prost(int64, tag = "18")]
            pub exchange_received_amount: i64,
            #[prost(int64, tag = "19")]
            pub exchange_inject_another_amount: i64,
            #[prost(int64, tag = "20")]
            pub exchange_withdraw_another_amount: i64,
            #[prost(int64, tag = "21")]
            pub exchange_id: i64,
            #[prost(int64, tag = "22")]
            pub shielded_transaction_fee: i64,
            #[prost(bytes = "vec", tag = "25")]
            pub order_id: Vec<u8>,
            #[prost(int64, repeated, tag = "26")]
            pub order_details: Vec<i64>,
        }

        pub mod result {
            /// Result codes
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
            #[repr(i32)]
            pub enum Code {
                #[default]
                Success = 0,
                Failed = 1,
            }

            impl TryFrom<i32> for Code {
                type Error = ();

                fn try_from(value: i32) -> Result<Self, Self::Error> {
                    match value {
                        0 => Ok(Code::Success),
                        1 => Ok(Code::Failed),
                        _ => Err(()),
                    }
                }
            }

            impl From<Code> for i32 {
                fn from(value: Code) -> Self {
                    value as i32
                }
            }

            /// Contract result codes
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
            #[repr(i32)]
            pub enum ContractResult {
                #[default]
                Default = 0,
                Success = 1,
                Revert = 2,
                BadJumpDestination = 3,
                OutOfMemory = 4,
                PrecompiledContract = 5,
                StackTooSmall = 6,
                StackTooLarge = 7,
                IllegalOperation = 8,
                StackOverflow = 9,
                OutOfEnergy = 10,
                OutOfTime = 11,
                JvmStackOverFlow = 12,
                Unknown = 13,
                TransferFailed = 14,
                InvalidCode = 15,
            }

            impl TryFrom<i32> for ContractResult {
                type Error = ();

                fn try_from(value: i32) -> Result<Self, Self::Error> {
                    match value {
                        0 => Ok(ContractResult::Default),
                        1 => Ok(ContractResult::Success),
                        2 => Ok(ContractResult::Revert),
                        3 => Ok(ContractResult::BadJumpDestination),
                        4 => Ok(ContractResult::OutOfMemory),
                        5 => Ok(ContractResult::PrecompiledContract),
                        6 => Ok(ContractResult::StackTooSmall),
                        7 => Ok(ContractResult::StackTooLarge),
                        8 => Ok(ContractResult::IllegalOperation),
                        9 => Ok(ContractResult::StackOverflow),
                        10 => Ok(ContractResult::OutOfEnergy),
                        11 => Ok(ContractResult::OutOfTime),
                        12 => Ok(ContractResult::JvmStackOverFlow),
                        13 => Ok(ContractResult::Unknown),
                        14 => Ok(ContractResult::TransferFailed),
                        15 => Ok(ContractResult::InvalidCode),
                        _ => Err(()),
                    }
                }
            }

            impl From<ContractResult> for i32 {
                fn from(value: ContractResult) -> Self {
                    value as i32
                }
            }
        }
    }

    /// Transfer contract for TRX transfers
    #[derive(Clone, PartialEq, Message)]
    pub struct TransferContract {
        #[prost(bytes = "vec", tag = "1")]
        pub owner_address: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub to_address: Vec<u8>,
        #[prost(int64, tag = "3")]
        pub amount: i64,
    }

    /// Smart contract trigger (call)
    #[derive(Clone, PartialEq, Message)]
    pub struct TriggerSmartContract {
        #[prost(bytes = "vec", tag = "1")]
        pub owner_address: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub contract_address: Vec<u8>,
        #[prost(int64, tag = "3")]
        pub call_value: i64,
        #[prost(bytes = "vec", tag = "4")]
        pub data: Vec<u8>,
        #[prost(int64, tag = "5")]
        pub call_token_value: i64,
        #[prost(int64, tag = "6")]
        pub token_id: i64,
    }

    /// Authority for multi-sig
    #[derive(Clone, PartialEq, Message)]
    pub struct Authority {
        #[prost(bytes = "vec", tag = "1")]
        pub account: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub permission_name: Vec<u8>,
    }

    /// Block header
    #[derive(Clone, PartialEq, Message)]
    pub struct BlockHeader {
        #[prost(message, optional, tag = "1")]
        pub raw_data: Option<block_header::Raw>,
        #[prost(bytes = "vec", tag = "2")]
        pub witness_signature: Vec<u8>,
    }

    pub mod block_header {
        use prost::Message;

        /// Raw block header data
        #[derive(Clone, PartialEq, Message)]
        pub struct Raw {
            #[prost(int64, tag = "1")]
            pub timestamp: i64,
            #[prost(bytes = "vec", tag = "2")]
            pub tx_trie_root: Vec<u8>,
            #[prost(bytes = "vec", tag = "3")]
            pub parent_hash: Vec<u8>,
            #[prost(int64, tag = "7")]
            pub number: i64,
            #[prost(int64, tag = "8")]
            pub witness_id: i64,
            #[prost(bytes = "vec", tag = "9")]
            pub witness_address: Vec<u8>,
            #[prost(int32, tag = "10")]
            pub version: i32,
            #[prost(bytes = "vec", tag = "11")]
            pub account_state_root: Vec<u8>,
        }
    }

    /// Block
    #[derive(Clone, PartialEq, Message)]
    pub struct Block {
        #[prost(message, repeated, tag = "1")]
        pub transactions: Vec<Transaction>,
        #[prost(message, optional, tag = "2")]
        pub block_header: Option<BlockHeader>,
    }

    /// Return message for API calls
    #[derive(Clone, PartialEq, Message)]
    pub struct Return {
        #[prost(bool, tag = "1")]
        pub result: bool,
        #[prost(enumeration = "r#return::Code", tag = "2")]
        pub code: i32,
        #[prost(string, tag = "3")]
        pub message: String,
        #[prost(bytes = "vec", tag = "4")]
        pub txid: Vec<u8>,
    }

    pub mod r#return {
        /// Return codes
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        #[repr(i32)]
        pub enum Code {
            #[default]
            Success = 0,
            SigError = 1,
            ContractValidateError = 2,
            ContractExeError = 3,
            BandwidthError = 4,
            DupTransactionError = 5,
            TaposError = 6,
            TooBigTransactionError = 7,
            TransactionExpirationError = 8,
            ServerBusy = 9,
            NoConnection = 10,
            NotEnoughEffectiveConnection = 11,
            OtherError = 20,
        }

        impl TryFrom<i32> for Code {
            type Error = ();

            fn try_from(value: i32) -> Result<Self, Self::Error> {
                match value {
                    0 => Ok(Code::Success),
                    1 => Ok(Code::SigError),
                    2 => Ok(Code::ContractValidateError),
                    3 => Ok(Code::ContractExeError),
                    4 => Ok(Code::BandwidthError),
                    5 => Ok(Code::DupTransactionError),
                    6 => Ok(Code::TaposError),
                    7 => Ok(Code::TooBigTransactionError),
                    8 => Ok(Code::TransactionExpirationError),
                    9 => Ok(Code::ServerBusy),
                    10 => Ok(Code::NoConnection),
                    11 => Ok(Code::NotEnoughEffectiveConnection),
                    20 => Ok(Code::OtherError),
                    _ => Err(()),
                }
            }
        }

        impl From<Code> for i32 {
            fn from(value: Code) -> Self {
                value as i32
            }
        }
    }

    /// Empty message for parameterless calls
    #[derive(Clone, PartialEq, Message)]
    pub struct EmptyMessage {}

    /// Number message for block queries
    #[derive(Clone, PartialEq, Message)]
    pub struct NumberMessage {
        #[prost(int64, tag = "1")]
        pub num: i64,
    }

    /// Simplified Wallet gRPC client
    #[cfg(feature = "tron")]
    pub struct WalletClient {
        endpoint: String,
    }

    #[cfg(feature = "tron")]
    impl WalletClient {
        pub fn new(endpoint: String) -> Self {
            Self { endpoint }
        }

        /// Broadcast a transaction via HTTP POST (simplified gRPC)
        pub async fn broadcast_transaction(
            &mut self,
            transaction: Transaction,
        ) -> Result<Return, Box<dyn std::error::Error + Send + Sync>> {
            // Serialize transaction to protobuf bytes
            let tx_bytes = transaction.encode_to_vec();
            
            // Make HTTP POST request to gRPC endpoint
            let client = reqwest::Client::new();
            let response = client
                .post(&format!("{}/protocol.Wallet/BroadcastTransaction", self.endpoint))
                .header("content-type", "application/grpc")
                .body(tx_bytes)
                .send()
                .await?;

            let response_bytes = response.bytes().await?;
            let result = Return::decode(&response_bytes[..])?;
            Ok(result)
        }

        /// Get latest block via HTTP POST (simplified gRPC)
        pub async fn get_now_block(
            &mut self,
        ) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
            let empty_msg = EmptyMessage {};
            let msg_bytes = empty_msg.encode_to_vec();
            
            let client = reqwest::Client::new();
            let response = client
                .post(&format!("{}/protocol.Wallet/GetNowBlock", self.endpoint))
                .header("content-type", "application/grpc")
                .body(msg_bytes)
                .send()
                .await?;

            let response_bytes = response.bytes().await?;
            let result = Block::decode(&response_bytes[..])?;
            Ok(result)
        }
    }
} 