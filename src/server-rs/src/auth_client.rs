//! Port of `src/server/lib/auth-client.ts` (being written separately; this
//! file only fixes the interface `sso.rs` is written against).

use serde_json::{Map, Value};

pub struct AuthClientOptions {
    pub issuer: String,
    pub back_channel_url: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub audience: Option<String>,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidGrant(String),
    Unavailable(String),
    InvalidToken(String),
    Login { code: &'static str, error: Option<String> },
    Other(String),
}

impl AuthError {
    pub fn message(&self) -> String {
        match self {
            AuthError::InvalidGrant(m) | AuthError::Unavailable(m) | AuthError::InvalidToken(m) | AuthError::Other(m) => m.clone(),
            AuthError::Login { code, error } => match error {
                Some(error) => format!("{code}: {error}"),
                None => (*code).to_string(),
            },
        }
    }
}

pub struct AccessClaims {
    pub sub: String,
    pub sid: String,
    pub username: String,
    pub name: String,
    pub role: String,
    pub all: Map<String, Value>,
}

pub struct IdClaims {
    pub email: Option<Value>,
    pub email_verified: Option<Value>,
    pub all: Map<String, Value>,
}

pub struct Login {
    pub claims: AccessClaims,
    pub id_claims: IdClaims,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub return_to: String,
    pub clear_cookie: String,
}

pub struct Refreshed {
    pub claims: AccessClaims,
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub struct AuthEvent {
    pub type_: String,
    pub jti: String,
    pub sub: Option<String>,
    pub sid: Option<String>,
    pub role: Option<Option<String>>,
    pub id: Option<String>,
    pub invite: Option<String>,
}

#[derive(Default)]
pub struct StartLoginOptions {
    pub return_to: Option<String>,
    pub max_age: Option<f64>,
    pub prompt: Option<String>,
    pub login_hint: Option<String>,
}

pub struct StartedLogin {
    pub redirect_url: String,
    pub login_cookie: String,
}

pub struct AuthClient {}

fn pending<T>() -> Result<T, AuthError> {
    Err(AuthError::Unavailable("single sign-on is not available in this build".into()))
}

impl AuthClient {
    pub fn new(_options: AuthClientOptions) -> Result<AuthClient, String> {
        Ok(AuthClient {})
    }

    pub async fn start_login(&self, _options: StartLoginOptions) -> Result<StartedLogin, AuthError> {
        pending()
    }

    pub async fn finish_login(&self, _cookie_header: Option<&str>, _query: &[(String, String)]) -> Result<Login, AuthError> {
        pending()
    }

    pub async fn refresh(&self, _refresh_token: &str) -> Result<Refreshed, AuthError> {
        pending()
    }

    pub async fn revoke(&self, _refresh_token: &str) -> Result<(), AuthError> {
        pending()
    }

    pub async fn read_event(&self, _body: &str) -> Result<AuthEvent, AuthError> {
        pending()
    }

    pub async fn logout_url(&self, _post_logout_redirect: Option<&str>) -> Result<String, AuthError> {
        pending()
    }
}
