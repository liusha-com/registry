//! Separate server-rendered documents with page-specific enhancements.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
pub fn render(path: &str) -> Option<String> {
    let (title, page, body) = match path {
        "/" => (
            "Portable code. Shared openly.",
            "home",
            include_str!("../ui/pages/home.html"),
        ),
        "/explore" => (
            "Explore packages",
            "explore",
            include_str!("../ui/pages/explore.html"),
        ),
        "/register" => (
            "Create your account",
            "register",
            include_str!("../ui/pages/register.html"),
        ),
        "/login" => (
            "Welcome back",
            "login",
            include_str!("../ui/pages/login.html"),
        ),
        "/account" => (
            "Your account",
            "account",
            include_str!("../ui/pages/account.html"),
        ),
        "/publish" => (
            "Publish a package",
            "publish",
            include_str!("../ui/pages/publish.html"),
        ),
        "/docs" => (
            "Getting started",
            "docs",
            include_str!("../ui/pages/docs.html"),
        ),
        p if p.starts_with("/packages/") => {
            let parts: Vec<_> = p.split('/').collect();
            if !(parts.len() == 4 || parts.len() == 5) || parts[2..].iter().any(|p| p.is_empty()) {
                return None;
            }
            if parts.len() == 5 {
                (
                    "Release details",
                    "release",
                    include_str!("../ui/pages/release.html"),
                )
            } else {
                (
                    "Package details",
                    "package",
                    include_str!("../ui/pages/package.html"),
                )
            }
        }
        _ => return None,
    };
    Some(
        include_str!("../ui/layout.html")
            .replace("{{title}}", title)
            .replace("{{page}}", page)
            .replace("{{body}}", body),
    )
}
