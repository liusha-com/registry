//! Portable account and session storage shared by native and WASI HTTP builds.
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub type Headers = BTreeMap<String, String>;
type Result<T> = std::result::Result<T, Error>;
const SESSION_SECONDS: u64 = 86400;
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRmb3JkdW1teQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug)]
pub struct Error {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}
pub fn error(status: u16, code: &'static str, message: &str) -> Error {
    Error {
        status,
        code,
        message: message.into(),
    }
}
fn storage_error(_: impl std::fmt::Display) -> Error {
    error(500, "account_storage", "Account storage is unavailable.")
}
fn unauthorized() -> Error {
    error(401, "unauthorized", "Sign in to continue.")
}
#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    pub origin: String,
}
#[derive(Default, Serialize, Deserialize)]
struct Data {
    users: BTreeMap<String, User>,
    credentials: BTreeMap<String, Credential>,
    attempts: BTreeMap<String, (u64, u32)>,
}
#[derive(Serialize, Deserialize)]
struct User {
    password: String,
    created_at: u64,
    #[serde(default)]
    email: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Credential {
    id: String,
    username: String,
    name: String,
    expires_at: u64,
    created_at: u64,
    session: bool,
}
pub struct Identity {
    pub username: String,
    pub session: bool,
}
pub struct Reply {
    pub status: u16,
    pub headers: Headers,
    pub body: Value,
}
pub struct DirectoryLock(PathBuf);

#[cfg(all(test, not(target_arch = "wasm32")))]
mod email_tests {
    use super::*;
    #[test]
    fn only_email_credentials_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("accounts.json"), "http://localhost:8080");
        let headers = Headers::from([("content-type".into(), "application/json".into())]);
        let call = |path: &str, value: Value| {
            store.handle("POST", path, &headers, &serde_json::to_vec(&value).unwrap())
        };
        let password = "correct-horse-1234";
        let registered = call(
            "/v1/auth/register",
            json!({"email":" Alice@Example.com ","password":password}),
        )
        .unwrap();
        assert_eq!(registered.status, 201);
        let id = &registered.body["user"]["username"];
        assert!(id.as_str().unwrap().starts_with("u-"));
        let login = call(
            "/v1/auth/login",
            json!({"email":"ALICE@example.com","password":password}),
        )
        .unwrap();
        assert_eq!(&login.body["user"]["username"], id);
        for path in ["/v1/auth/register", "/v1/auth/login"] {
            for input in [
                json!({"username":id,"password":password}),
                json!({"username":"alice@example.com","password":password}),
                json!({"email":"alice@example.com","username":"alice","password":password}),
                json!({"password":password}),
            ] {
                assert!(matches!(call(path, input), Err(Error { status: 400, .. })));
            }
        }
        assert!(matches!(
            call(
                "/v1/auth/register",
                json!({"email":"alice@example.com","password":password})
            ),
            Err(Error { status: 409, .. })
        ));
        assert!(matches!(
            call(
                "/v1/auth/login",
                json!({"email":"nobody@example.com","password":password})
            ),
            Err(Error { status: 401, .. })
        ));
        let legacy: User = serde_json::from_str(r#"{"password":"legacy","created_at":0}"#).unwrap();
        assert!(legacy.email.is_none());
    }
}
impl DirectoryLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        fs::create_dir(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                error(
                    503,
                    "storage_busy",
                    "Storage is busy. Please retry shortly.",
                )
            } else {
                storage_error(e)
            }
        })?;
        Ok(Self(path.to_owned()))
    }
}
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}
pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn random_secret() -> Result<String> {
    #[cfg(target_arch = "wasm32")]
    let bytes = wasip2::random::random::get_random_bytes(32);
    #[cfg(not(target_arch = "wasm32"))]
    let bytes = {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(storage_error)?;
        bytes.to_vec()
    };
    Ok(hex::encode(bytes))
}
fn digest(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}
fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, None).expect("fixed password parameters"),
    )
}
fn csrf(secret: &str) -> String {
    digest(&format!("registry-csrf:{secret}"))
}
fn credential(headers: &Headers) -> Option<(&str, bool)> {
    if let Some(value) = headers.get("authorization") {
        return value.strip_prefix("Bearer ").map(|v| (v, false));
    }
    headers.get("cookie")?.split(';').find_map(|v| {
        v.trim()
            .strip_prefix("registry_session=")
            .map(|s| (s, true))
    })
}
impl Store {
    pub fn new(path: PathBuf, origin: &str) -> Self {
        Self {
            path,
            origin: origin.trim_end_matches('/').to_owned(),
        }
    }
    fn load(&self) -> Result<Data> {
        match fs::File::open(&self.path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(storage_error)?;
                if bytes.len() > 16 * 1024 * 1024 {
                    return Err(storage_error("state limit"));
                }
                serde_json::from_slice(&bytes).map_err(storage_error)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Data::default()),
            Err(e) => Err(storage_error(e)),
        }
    }
    fn change<T>(&self, action: impl FnOnce(&mut Data) -> Result<T>) -> Result<T> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let _lock = DirectoryLock::acquire(&self.path.with_extension("lock"))?;
        let mut data = self.load()?;
        data.credentials.retain(|_, c| c.expires_at > timestamp());
        data.attempts
            .retain(|_, (start, _)| timestamp().saturating_sub(*start) < 900);
        let value = action(&mut data)?;
        let bytes = serde_json::to_vec(&data).map_err(storage_error)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(error(
                503,
                "account_limit",
                "Account storage capacity has been reached.",
            ));
        }
        let temp = self.path.with_extension("pending");
        let mut file = fs::File::create(&temp).map_err(storage_error)?;
        file.write_all(&bytes).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        drop(file);
        fs::rename(&temp, &self.path).map_err(storage_error)?;
        Ok(value)
    }
    pub fn identify(&self, headers: &Headers, mutation: bool) -> Result<Identity> {
        let (secret, cookie) = credential(headers).ok_or_else(unauthorized)?;
        let data = self.load()?;
        let c = data
            .credentials
            .get(&digest(secret))
            .filter(|c| c.expires_at > timestamp())
            .ok_or_else(unauthorized)?;
        // Session secrets are cookie-only; personal API tokens are bearer-only.
        if cookie != c.session {
            return Err(unauthorized());
        }
        if cookie && mutation {
            self.check_origin(headers)?;
            if headers.get("x-csrf-token") != Some(&csrf(secret)) {
                return Err(error(
                    403,
                    "csrf_required",
                    "Refresh the page and retry this action.",
                ));
            }
        }
        Ok(Identity {
            username: c.username.clone(),
            session: c.session,
        })
    }
    fn check_origin(&self, headers: &Headers) -> Result<()> {
        if headers.get("origin").is_some_and(|v| v != &self.origin) {
            return Err(error(
                403,
                "origin_rejected",
                "This request came from a different origin.",
            ));
        }
        Ok(())
    }
    fn cookie(&self, secret: &str, lifetime: u64) -> String {
        format!(
            "registry_session={secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age={lifetime}{}",
            if self.origin.starts_with("https://") {
                "; Secure"
            } else {
                ""
            }
        )
    }
    fn issue(
        data: &mut Data,
        username: &str,
        name: &str,
        session: bool,
    ) -> Result<(String, String)> {
        if data
            .credentials
            .values()
            .filter(|c| c.username == username)
            .count()
            >= 30
        {
            return Err(error(
                429,
                "credential_limit",
                "Revoke an existing token or session before creating another.",
            ));
        }
        let secret = format!(
            "{}{}",
            if session { "wrs_" } else { "wrt_" },
            random_secret()?
        );
        let id = format!(
            "{}{}",
            if session { "ses_" } else { "pat_" },
            &random_secret()?[..24]
        );
        data.credentials.insert(
            digest(&secret),
            Credential {
                id: id.clone(),
                username: username.into(),
                name: name.into(),
                session,
                created_at: timestamp(),
                expires_at: timestamp()
                    + if session {
                        SESSION_SECONDS
                    } else {
                        90 * SESSION_SECONDS
                    },
            },
        );
        Ok((secret, id))
    }
    #[allow(clippy::too_many_lines)]
    pub fn handle(
        &self,
        method: &str,
        path: &str,
        headers: &Headers,
        body: &[u8],
    ) -> Result<Reply> {
        if body.len() > 8192 {
            return Err(error(
                413,
                "body_too_large",
                "Account requests are limited to 8 KiB.",
            ));
        }
        if !matches!(method, "GET" | "HEAD") {
            self.check_origin(headers)?;
            if method == "POST"
                && headers
                    .get("content-type")
                    .is_none_or(|v| v.split(';').next() != Some("application/json"))
            {
                return Err(error(
                    415,
                    "json_required",
                    "Send an application/json request.",
                ));
            }
        }
        let mut reply = Reply {
            status: 200,
            headers: Headers::from([("cache-control".into(), "no-store".into())]),
            body: json!({}),
        };
        if method == "GET" && path == "/v1/auth/providers" {
            reply.body = json!({"email_password":true,"github":false});
            return Ok(reply);
        }
        if method == "POST" && matches!(path, "/v1/auth/register" | "/v1/auth/login") {
            let value: Value = serde_json::from_slice(body)
                .map_err(|_| error(400, "invalid_json", "The request body is not valid JSON."))?;
            let register = path.ends_with("register");
            let email = value["email"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if value.get("username").is_some() {
                return Err(error(
                    400,
                    "email_required",
                    "Use an email address to register or sign in.",
                ));
            }
            if email.is_empty()
                || email.len() > 254
                || email.chars().any(char::is_whitespace)
                || email.split_once('@').is_none_or(|(local, domain)| {
                    local.is_empty()
                        || !domain.contains('.')
                        || domain.contains('@')
                        || domain.split('.').any(str::is_empty)
                })
            {
                return Err(error(400, "invalid_email", "Enter a valid email address."));
            }
            let username = if register {
                format!("u-{}", &random_secret()?[..24])
            } else {
                self.load()?
                    .users
                    .iter()
                    .find(|(_, user)| user.email.as_deref() == Some(email.as_str()))
                    .map_or_else(|| email.clone(), |(name, _)| name.clone())
            };
            let password = value["password"].as_str().unwrap_or_default();
            if password.chars().count() < 12 || password.len() > 128 {
                return Err(error(
                    400,
                    "invalid_password",
                    "Use at least 12 characters and no more than 128 UTF-8 bytes.",
                ));
            }
            self.change(|data| {
                if data.attempts.len() >= 2048 && !data.attempts.contains_key(&email) {
                    return Err(error(
                        429,
                        "rate_limited",
                        "Too many authentication attempts. Try again later.",
                    ));
                }
                let (_, count) = data
                    .attempts
                    .entry(email.clone())
                    .or_insert((timestamp(), 0));
                if *count >= 8 {
                    return Err(error(
                        429,
                        "rate_limited",
                        "Too many attempts. Try again in 15 minutes.",
                    ));
                }
                *count += 1;
                Ok(())
            })?;
            let data = self.load()?;
            let stored = data.users.get(&username);
            if register && stored.is_some() {
                return Err(error(
                    409,
                    "account_unavailable",
                    "Unable to create the account. Try again.",
                ));
            }
            let password_hash = if register {
                let salt =
                    SaltString::encode_b64(&hex::decode(random_secret()?).map_err(storage_error)?)
                        .map_err(storage_error)?;
                Some(
                    argon()
                        .hash_password(password.as_bytes(), &salt)
                        .map_err(storage_error)?
                        .to_string(),
                )
            } else {
                let encoded = stored.map_or(DUMMY_HASH, |u| u.password.as_str());
                let parsed = PasswordHash::new(encoded).map_err(storage_error)?;
                let valid = argon()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok();
                if !valid || stored.is_none() {
                    return Err(error(
                        401,
                        "invalid_credentials",
                        "Email or password is incorrect.",
                    ));
                }
                None
            };
            let (secret, _) = self.change(|data| {
                if let Some(password) = password_hash {
                    if !email.is_empty()
                        && data
                            .users
                            .values()
                            .any(|user| user.email.as_deref() == Some(email.as_str()))
                    {
                        return Err(error(
                            409,
                            "account_unavailable",
                            "This email is already in use.",
                        ));
                    }
                    if data.users.contains_key(&username) {
                        return Err(error(
                            409,
                            "account_unavailable",
                            "Unable to create the account. Try again.",
                        ));
                    }
                    if data.users.len() >= 10000 {
                        return Err(error(
                            503,
                            "account_limit",
                            "Registration capacity has been reached.",
                        ));
                    }
                    data.users.insert(
                        username.clone(),
                        User {
                            password,
                            created_at: timestamp(),
                            email: if email.is_empty() {
                                None
                            } else {
                                Some(email.clone())
                            },
                        },
                    );
                }
                data.attempts.remove(&email);
                Self::issue(data, &username, "Browser session", true)
            })?;
            reply.status = if register { 201 } else { 200 };
            reply
                .headers
                .insert("set-cookie".into(), self.cookie(&secret, SESSION_SECONDS));
            reply.body = json!({"user":{"username":username,"email":email},"csrf_token":csrf(&secret),"expires_in":SESSION_SECONDS});
            return Ok(reply);
        }
        let identity = self.identify(headers, method != "GET")?;
        match (method, path) {
            ("GET", "/v1/auth/me") => {
                let data = self.load()?;
                let user = data
                    .users
                    .get(&identity.username)
                    .ok_or_else(unauthorized)?;
                reply.body = json!({"user":{"username":identity.username,"email":user.email,"created_at":user.created_at},
                    "csrf_token": if identity.session { credential(headers).map(|(s,_)|csrf(s)) } else {None} });
            }
            ("POST", "/v1/auth/logout") => {
                let (secret, _) = credential(headers).ok_or_else(unauthorized)?;
                self.change(|data| {
                    data.credentials.remove(&digest(secret));
                    Ok(())
                })?;
                reply
                    .headers
                    .insert("set-cookie".into(), self.cookie("", 0));
                reply.body = json!({"signed_out":true});
            }
            ("GET", "/v1/account/tokens") => {
                let data = self.load()?;
                reply.body = json!({"tokens":data.credentials.values().filter(|c| c.username == identity.username && !c.session && c.expires_at > timestamp()).map(|c| json!({"id":c.id,"name":c.name,"created_at":c.created_at,"expires_at":c.expires_at})).collect::<Vec<_>>()});
            }
            ("POST", "/v1/account/tokens") if identity.session => {
                let value: Value = serde_json::from_slice(body).map_err(|_| {
                    error(400, "invalid_json", "The request body is not valid JSON.")
                })?;
                let name = value["name"].as_str().unwrap_or_default().trim();
                if name.is_empty() || name.len() > 64 {
                    return Err(error(
                        400,
                        "invalid_token_name",
                        "Enter a token name of 1–64 bytes.",
                    ));
                }
                let (secret, id) =
                    self.change(|data| Self::issue(data, &identity.username, name, false))?;
                reply.status = 201;
                reply.body = json!({"id":id,"token":secret,"expires_in":90*SESSION_SECONDS});
            }
            ("DELETE", path) if path.starts_with("/v1/account/tokens/") && identity.session => {
                let id = path.trim_start_matches("/v1/account/tokens/");
                self.change(|data| {
                    let hash = data
                        .credentials
                        .iter()
                        .find(|(_, c)| c.id == id && c.username == identity.username && !c.session)
                        .map(|(h, _)| h.clone())
                        .ok_or_else(|| error(404, "not_found", "Token not found."))?;
                    data.credentials.remove(&hash);
                    Ok(())
                })?;
                reply.body = json!({"revoked":true});
            }
            _ => return Err(error(404, "not_found", "Account endpoint not found.")),
        }
        Ok(reply)
    }
}
