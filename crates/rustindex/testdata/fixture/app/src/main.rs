//! Fixture app: one function per site class / dispatch shape rustindex must
//! handle. Line positions matter to the golden tests; append, don't reorder.

use reqwest::Client;
use sqlx::{Executor, PgPool};
use std::time::Duration;

/// G1, high tier: inherent method on a concrete external type.
async fn fetch_user(client: &Client) -> Result<(), reqwest::Error> {
    let resp = client.get("https://api.example.com/user").send().await?;
    let _ = resp;
    Ok(())
}

/// G1, RC-019 evidence: a call-site timeout as a literal const arg.
async fn fetch_bounded(client: &Client) -> Result<(), reqwest::Error> {
    let resp = client
        .get("https://api.example.com/health")
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    let _ = resp;
    Ok(())
}

/// G1, trait-vs-impl probe: a trait method called on a CONCRETE receiver.
fn query_direct(pool: &PgPool) -> u64 {
    pool.execute("SELECT 1")
}

/// G1, mid tier: dyn-Trait dispatch, resolvable only to the trait method.
fn query_dyn(e: &dyn Executor) -> u64 {
    e.execute("SELECT 2")
}

/// G1, abstain tier: generic receiver, no instantiation at the site.
fn query_generic<E: Executor>(e: &E) -> u64 {
    e.execute("SELECT 3")
}

/// G1: redis cache client calls.
fn cache_lookup(conn: &mut redis::Connection) -> String {
    conn.set("k", "v");
    conn.get("k")
}

/// RC-019 evidence: client-config timeout at construction.
fn build_client() -> reqwest::Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

/// RC-019 evidence: pool acquire_timeout at construction.
fn build_pool() -> PgPool {
    sqlx::pool::PoolOptions::new()
        .acquire_timeout(Duration::from_secs(3))
        .connect("postgres://localhost/app")
}

/// G2: server-entry route registrations.
fn routes() -> axum::Router {
    axum::Router::new()
        .route("/users", axum::routing::get(list_users))
        .route("/users", axum::routing::post(create_user))
}

fn list_users() {}
fn create_user() {}

/// G3: background worker loop.
fn spawn_worker() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    tokio::task::spawn_blocking(|| {});
}

/// G4: emission points via macros (macro-expansion territory).
fn observe() {
    tracing::info!("starting");
    tracing::info!("connected");
    tracing::error!("failed");
}

fn main() {
    let client = build_client();
    let pool = build_pool();
    let _ = fetch_user(&client);
    let _ = fetch_bounded(&client);
    let _ = query_direct(&pool);
    let _ = query_dyn(&pool);
    let _ = query_generic(&pool);
    let mut conn = redis::Client::open("redis://localhost").get_connection();
    let _ = cache_lookup(&mut conn);
    let _ = routes();
    spawn_worker();
    observe();
}
