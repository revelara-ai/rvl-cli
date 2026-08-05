//! Surface-only stub of sqlx: a trait-dispatch shape (Executor) plus the
//! pool-options identity the RC-019 seed spec names (acquire_timeout).

pub trait Executor {
    fn execute(&self, sql: &str) -> u64;
}

pub struct PgPool;

impl PgPool {
    pub fn connect(_url: &str) -> PgPool {
        PgPool
    }
    #[allow(clippy::unused_async)]
    pub async fn acquire(&self) -> PoolConnection {
        PoolConnection
    }
}

impl Executor for PgPool {
    fn execute(&self, _sql: &str) -> u64 {
        0
    }
}

pub struct PoolConnection;

pub mod pool {
    pub struct PoolOptions;
    impl PoolOptions {
        #[allow(clippy::new_without_default)]
        pub fn new() -> PoolOptions {
            PoolOptions
        }
        pub fn acquire_timeout(self, _d: core::time::Duration) -> PoolOptions {
            self
        }
        pub fn connect(self, _url: &str) -> super::PgPool {
            super::PgPool
        }
    }
}
