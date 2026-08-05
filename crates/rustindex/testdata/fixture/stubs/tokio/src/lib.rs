//! Surface-only stub of tokio: the spawn family and a sleep, enough for the
//! G3 background-job monikers.

pub fn spawn<F>(_f: F) {}

pub mod task {
    pub fn spawn_blocking<F>(_f: F) {}
}

pub mod time {
    #[allow(clippy::unused_async)]
    pub async fn sleep(_d: core::time::Duration) {}
}
