use thiserror::Error;

#[derive(Error, Debug)]
pub enum LijError {
    #[error("Key error: {0}")]
    Key(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("LSP error: {0}")]
    Lsp(String),

    #[error("Node error: {0}")]
    Node(String),

    #[error("Payment error: {0}")]
    Payment(String),

    #[error("Invoice error: {0}")]
    Invoice(String),

    #[error("Backup error: {0}")]
    Backup(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Not initialized")]
    NotInitialized,
    #[error("Sync state not ready: {0}")]
    SyncStateNotReady(String),
}

pub type LijResult<T> = Result<T, LijError>;
