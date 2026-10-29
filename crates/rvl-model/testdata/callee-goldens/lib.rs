use std::time::Duration;

pub struct Pool;

pub(crate) fn connect(url: &str) -> Pool {
    let _ = url;
    Pool
}

async fn send<T>(pool: &Pool, body: T) -> Result<(), String> {
    let _ = (pool, body);
    Ok(())
}

fn timeout() -> Duration {
    Duration::from_secs(5)
}

pub async fn run(url: &str) -> Result<(), String> {
    let pool = connect(url);
    send(&pool, "x").await?;
    std::thread::sleep(timeout());
    Ok(())
}
