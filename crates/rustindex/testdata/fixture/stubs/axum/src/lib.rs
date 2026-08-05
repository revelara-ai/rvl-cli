//! Surface-only stub of axum: Router::route plus the routing method helpers,
//! enough for the G2 server-entry monikers.

pub struct Router;

impl Router {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Router {
        Router
    }
    pub fn route(self, _path: &str, _m: MethodRouter) -> Router {
        self
    }
}

pub struct MethodRouter;

pub mod routing {
    use super::MethodRouter;
    pub fn get<H>(_h: H) -> MethodRouter {
        MethodRouter
    }
    pub fn post<H>(_h: H) -> MethodRouter {
        MethodRouter
    }
    pub fn put<H>(_h: H) -> MethodRouter {
        MethodRouter
    }
    pub fn delete<H>(_h: H) -> MethodRouter {
        MethodRouter
    }
}
