/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    http::HttpRequest,
    imap::{ImapConnection, Type},
    pop3::Pop3Connection,
    server::TestServer,
    smtp::SmtpConnection,
};
use base64::{Engine, engine::general_purpose};
use biscuit::{JWT, SingleOrMultiple, jwk::JWKSet};
use bytes::Bytes;
use common::auth::oauth::{
    introspect::OAuthIntrospect,
    oidc::StandardClaims,
    registration::{ClientRegistrationRequest, ClientRegistrationResponse},
};
use http::auth::oauth::{
    DeviceAuthResponse, ErrorType, TokenResponse,
    auth::{LoginRequest, LoginResponse},
};
use imap_proto::ResponseType;
use jmap_client::{
    client::{Client, Credentials},
    mailbox::query::Filter,
};
use registry::schema::{
    enums::JwtSignatureAlgorithm,
    prelude::{ObjectType, Property},
    structs::{OidcProvider, SecretText, SecretTextValue},
};
use serde::{Serialize, de::DeserializeOwned};
use std::time::{Duration, Instant};
use store::ahash::AHashMap;

#[derive(Debug, serde::Deserialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub introspection_endpoint: String,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct OpenIdMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub device_authorization_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

pub async fn test(test: &mut TestServer) {
    println!("Running OIDC tests...");

    let admin = test.account("admin@example.org");

    // Set test parameters
    let settings = OidcProvider {
        access_token_expiry: registry::schema::prelude::Duration::from_millis(1000),
        auth_code_expiry: registry::schema::prelude::Duration::from_millis(1000),
        auth_code_max_attempts: 1,
        user_code_expiry: registry::schema::prelude::Duration::from_millis(1000),
        refresh_token_expiry: registry::schema::prelude::Duration::from_millis(3000),
        refresh_token_renewal: registry::schema::prelude::Duration::from_millis(2000),
        anonymous_client_registration: true,
        require_client_registration: true,
        signature_algorithm: JwtSignatureAlgorithm::Rs256,
        signature_key: SecretText::Text(SecretTextValue {
            secret: OIDC_SIGNATURE_KEY_RS256.to_string(),
        }),
        ..Default::default()
    };
    admin
        .registry_update_setting(
            settings,
            &[
                Property::AccessTokenExpiry,
                Property::AuthCodeExpiry,
                Property::AuthCodeMaxAttempts,
                Property::UserCodeExpiry,
                Property::RefreshTokenExpiry,
                Property::RefreshTokenRenewal,
                Property::AnonymousClientRegistration,
                Property::RequireClientRegistration,
                Property::SignatureAlgorithm,
                Property::SignatureKey,
            ],
        )
        .await;
    admin.reload_settings().await;

    // Create test account
    let user = test
        .create_user_account(
            "admin@example.org",
            "user@example.org",
            "this is a very strong password",
            &[],
            "user@example.org",
        )
        .await;
    let user_id = user.id();

    // Build API
    let http = HttpRequest::new();

    // Obtain OAuth metadata
    let metadata: OAuthMetadata =
        get("https://127.0.0.1:8899/.well-known/oauth-authorization-server").await;
    let oidc_metadata: OpenIdMetadata =
        get("https://127.0.0.1:8899/.well-known/openid-configuration").await;
    let jwk_set: JWKSet<()> = get(&oidc_metadata.jwks_uri).await;

    // Register client
    let registration: ClientRegistrationResponse = post_json(
        &metadata.registration_endpoint,
        None,
        &ClientRegistrationRequest {
            redirect_uris: vec!["https://localhost".to_string()],
            ..Default::default()
        },
    )
    .await;
    let client_id = registration.client_id;

    /*println!("OAuth metadata: {:#?}", metadata);
    println!("OpenID metadata: {:#?}", oidc_metadata);
    println!("JWKSet: {:#?}", jwk_set);*/

    // ------------------------
    // Authorization code flow
    // ------------------------

    // Authenticate with the correct password
    let response = http
        .post::<LoginResponse>(
            "/api/auth",
            &LoginRequest::AuthCode {
                account_name: "user@example.org".to_string(),
                account_secret: "this is a very strong password".to_string(),
                mfa_token: None,
                client_id: client_id.to_string(),
                redirect_uri: "https://localhost".to_string().into(),
                nonce: "abc1234".to_string().into(),
                scope: None,
                code_challenge: None,
                code_challenge_method: None,
                state: None,
            },
        )
        .await
        .unwrap();

    // Both client_id and redirect_uri have to match
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), "invalid_client".to_string()),
        ("redirect_uri".to_string(), "https://localhost".to_string()),
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), response.unwrap_code()),
    ]);
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        }
    );
    token_params.insert("client_id".to_string(), client_id.to_string());
    token_params.insert(
        "redirect_uri".to_string(),
        "https://some-other.url".to_string(),
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        }
    );

    // Obtain token
    token_params.insert("redirect_uri".to_string(), "https://localhost".to_string());
    let (token, refresh_token, id_token) =
        unwrap_oidc_token_response(post(&metadata.token_endpoint, &token_params).await);

    // Connect to account using token and attempt to search
    let john_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(john_client.default_account_id(), user_id.to_string());
    assert!(
        !john_client
            .mailbox_query(None::<Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .is_empty()
    );

    // Verify ID token using the JWK set
    let id_token = JWT::<StandardClaims, biscuit::Empty>::new_encoded(&id_token)
        .decode_with_jwks(&jwk_set, None)
        .unwrap();
    let claims = id_token.payload().unwrap();
    let registered_claims = &claims.registered;
    let private_claims = &claims.private;
    assert_eq!(registered_claims.issuer, Some(oidc_metadata.issuer));
    assert_eq!(
        registered_claims.subject,
        Some(user_id.document_id().to_string())
    );
    assert_eq!(
        registered_claims.audience,
        Some(SingleOrMultiple::Single(client_id.to_string()))
    );
    assert_eq!(private_claims.nonce, Some("abc1234".into()));
    assert_eq!(
        private_claims.preferred_username,
        Some("user@example.org".into())
    );
    assert_eq!(private_claims.email, Some("user@example.org".into()));

    // Introspect token
    let access_introspect: OAuthIntrospect = post_with_auth::<OAuthIntrospect>(
        &metadata.introspection_endpoint,
        token.as_str().into(),
        &AHashMap::from_iter([("token".to_string(), token.to_string())]),
    )
    .await;
    assert_eq!(access_introspect.username.unwrap(), "user@example.org");
    assert_eq!(access_introspect.token_type.unwrap(), "bearer");
    assert_eq!(access_introspect.client_id.unwrap(), client_id);
    assert!(access_introspect.active);
    let refresh_introspect = post_with_auth::<OAuthIntrospect>(
        &metadata.introspection_endpoint,
        token.as_str().into(),
        &AHashMap::from_iter([("token".to_string(), refresh_token.unwrap())]),
    )
    .await;
    assert_eq!(refresh_introspect.username.unwrap(), "user@example.org");
    assert_eq!(refresh_introspect.client_id.unwrap(), client_id);
    assert!(refresh_introspect.active);
    assert_eq!(
        refresh_introspect.iat.unwrap(),
        access_introspect.iat.unwrap()
    );

    // Try SMTP OAUTHBEARER auth
    let oauth_bearer_invalid_sasl = general_purpose::STANDARD.encode(format!(
        "n,a={},\u{1}auth=Bearer {}\u{1}\u{1}",
        "user@domain", "invalid_token"
    ));
    let oauth_bearer_sasl = general_purpose::STANDARD.encode(format!(
        "n,a={},\u{1}auth=Bearer {}\u{1}\u{1}",
        "user@domain", token
    ));
    let mut smtp = SmtpConnection::connect().await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_invalid_sasl}",))
        .await;
    smtp.read(1, 4).await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}",))
        .await;
    smtp.read(1, 2).await;

    // Try IMAP OAUTHBEARER auth
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.send(&format!("AUTHENTICATE OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Try POP3 OAUTHBEARER auth
    let mut pop3 = Pop3Connection::connect().await;
    pop3.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    pop3.assert_read(crate::utils::pop3::ResponseType::Ok).await;

    // ------------------------
    // Device code flow
    // ------------------------

    // Request a device code
    let device_code_params =
        AHashMap::from_iter([("client_id".to_string(), client_id.to_string())]);
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    //println!("Device response: {:#?}", device_response);

    // Status should be pending
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), client_id.to_string()),
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        (
            "device_code".to_string(),
            device_response.device_code.to_string(),
        ),
    ]);
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::AuthorizationPending
        }
    );

    // Let the code expire and make sure it's invalidated
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        http.post::<LoginResponse>(
            "/api/auth",
            &LoginRequest::AuthDevice {
                account_name: "user@example.org".to_string(),
                account_secret: "this is a very strong password".to_string(),
                mfa_token: None,
                code: device_response.user_code.clone(),
            },
        )
        .await
        .unwrap(),
        LoginResponse::Failure
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::ExpiredToken
        }
    );

    // Authenticate account using a valid code
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    token_params.insert(
        "device_code".to_string(),
        device_response.device_code.to_string(),
    );
    assert_eq!(
        http.post::<LoginResponse>(
            "/api/auth",
            &LoginRequest::AuthDevice {
                account_name: "user@example.org".to_string(),
                account_secret: "this is a very strong password".to_string(),
                mfa_token: None,
                code: device_response.user_code.clone(),
            },
        )
        .await
        .unwrap(),
        LoginResponse::Verified
    );

    // Obtain token
    let time_first_token = Instant::now();
    let (token, refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &token_params).await);
    let refresh_token = refresh_token.unwrap();

    // Authorization codes can only be used once
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::ExpiredToken
        }
    );

    // Connect to account using token and attempt to search
    let john_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(john_client.default_account_id(), user_id.to_string());
    assert!(
        !john_client
            .mailbox_query(None::<Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .is_empty()
    );

    // Connecting using the refresh token should not work
    assert_unauthorized("https://127.0.0.1:8899", &refresh_token).await;

    // Refreshing a token using the access token should not work
    assert_eq!(
        post::<TokenResponse>(
            &metadata.token_endpoint,
            &AHashMap::from_iter([
                ("client_id".to_string(), client_id.to_string()),
                ("grant_type".to_string(), "refresh_token".to_string()),
                ("refresh_token".to_string(), token),
            ]),
        )
        .await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // Refreshing the access token before expiration should not include a new refresh token
    let refresh_params = AHashMap::from_iter([
        ("client_id".to_string(), client_id.to_string()),
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh_token),
    ]);
    let time_before_post: Instant = Instant::now();
    let (token, new_refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &refresh_params).await);
    assert_eq!(
        new_refresh_token,
        None,
        "Refreshed token in {:?}, since start {:?}",
        time_before_post.elapsed(),
        time_first_token.elapsed()
    );

    // Wait 1 second and make sure the access token expired
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_unauthorized("https://127.0.0.1:8899", &token).await;

    // Wait another second for the refresh token to be about to expire
    // and expect a new refresh token
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (_, new_refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &refresh_params).await);
    //println!("New refresh token: {:?}", new_refresh_token);
    assert_ne!(new_refresh_token, None);

    // Wait another second and make sure the refresh token expired
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &refresh_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // Clean up
    admin.registry_destroy_all(ObjectType::OAuthClient).await;
    admin.destroy_account(user).await;
    test.cleanup().await;
}

async fn post_bytes(
    url: &str,
    auth_token: Option<&str>,
    params: &AHashMap<String, String>,
) -> Bytes {
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url);

    if let Some(auth_token) = auth_token {
        client = client.bearer_auth(auth_token);
    }

    client
        .form(params)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn post_json<D: DeserializeOwned>(
    url: &str,
    auth_token: Option<&str>,
    body: &impl Serialize,
) -> D {
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url);

    if let Some(auth_token) = auth_token {
        client = client.bearer_auth(auth_token);
    }

    serde_json::from_slice(
        &client
            .body(serde_json::to_string(body).unwrap().into_bytes())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn post<T: DeserializeOwned>(url: &str, params: &AHashMap<String, String>) -> T {
    post_with_auth(url, None, params).await
}
async fn post_with_auth<T: DeserializeOwned>(
    url: &str,
    auth_token: Option<&str>,
    params: &AHashMap<String, String>,
) -> T {
    serde_json::from_slice(&post_bytes(url, auth_token, params).await).unwrap()
}

async fn get_bytes(url: &str) -> Bytes {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .get(url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn get<T: DeserializeOwned>(url: &str) -> T {
    serde_json::from_slice(&get_bytes(url).await).unwrap()
}

async fn assert_unauthorized(base_url: &str, token: &str) {
    match Client::new()
        .credentials(Credentials::bearer(token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect(base_url)
        .await
    {
        Ok(_) => panic!("Expected unauthorized access."),
        Err(err) => {
            let err = err.to_string();
            assert!(err.contains("Unauthorized"), "{}", err);
        }
    }
}

fn unwrap_token_response(response: TokenResponse) -> (String, Option<String>, u64) {
    match response {
        TokenResponse::Granted(granted) => {
            assert_eq!(granted.token_type, "bearer");
            (
                granted.access_token,
                granted.refresh_token,
                granted.expires_in,
            )
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}

fn unwrap_oidc_token_response(response: TokenResponse) -> (String, Option<String>, String) {
    match response {
        TokenResponse::Granted(granted) => {
            assert_eq!(granted.token_type, "bearer");
            (
                granted.access_token,
                granted.refresh_token,
                granted.id_token.unwrap(),
            )
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}

pub trait LoginResponseTest {
    fn unwrap_code(self) -> String;
}

impl LoginResponseTest for LoginResponse {
    fn unwrap_code(self) -> String {
        match self {
            LoginResponse::Authenticated { client_code } => client_code,
            _ => panic!("Expected auth code response, got {:?}", self),
        }
    }
}

const OIDC_SIGNATURE_KEY_RS256: &str = "-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDMXJI1bL3z8gaF
Ze/6493VjL+jHkFMP2Pc7fLwRF1fhkuIdYTp69LabzrSEJCRCz0UI2NHqPOgtOta
+zRHKAMr7c7Z6uKO0K+aXiQYHw4Y70uSG8CnmNl7kb4OM/CAcoO6fePmvBsyESfn
TmkJ5bfHEZQFDQEAoDlDjtjxuwYsAQQVQXuAydi8j8pyTWKAJ1RDgnUT+HbOub7j
JrQ7sPe6MPCjXv5N76v9RMHKktfYwRNMlkLkxImQU55+vlvghNztgFlIlJDFfNiy
UQPV5FTEZJli9BzMoj1JQK3sZyV8WV0W1zN41QQ+glAAC6+K7iTDPRMINBSwbHyn
6Lb9Q6U7AgMBAAECggEAB93qZ5xrhYgEFeoyKO4mUdGsu4qZyJB0zNeWGgdaXCfZ
zC4l8zFM+R6osix0EY6lXRtC95+6h9hfFQNa5FWseupDzmIQiEnim1EowjWef87l
Eayi0nDRB8TjqZKjR/aLOUhzrPlXHKrKEUk/RDkacCiDklwz9S0LIfLOSXlByBDM
/n/eczfX2gUATexMHSeIXs8vN2jpuiVv0r+FPXcRvqdzDZnYSzS8BJ9k6RYXVQ4o
NzCbfqgFIpVryB7nHgSTrNX9G7299If8/dXmesXWSFEJvvDSSpcBoINKbfgSlrxd
6ubjiotcEIBUSlbaanRrydwShhLHnXyupNAb7tlvyQKBgQDsIipSK4+H9FGl1rAk
Gg9DLJ7P/94sidhoq1KYnj/CxwGLoRq22khZEUYZkSvYXDu1Qkj9Avi3TRhw8uol
l2SK1VylL5FQvTLKhWB7b2hjrUd5llMRgS3/NIdLhOgDMB7w3UxJnCA/df/Rj+dM
WhkyS1f0x3t7XPLwWGurW0nJcwKBgQDdjhrNfabrK7OQvDpAvNJizuwZK9WUL7CD
rR0V0MpDGYW12BTEOY6tUK6XZgiRitAXf4EkEI6R0Q0bFzwDDLrg7TvGdTuzNeg/
8vm8IlRlOkrdihtHZI4uRB7Ytmz24vzywEBE0p6enA7v4oniscUks/KKmDGr0V90
yT9gIVrjGQKBgQCjnWC5otlHGLDiOgm+WhgtMWOxN9dYAQNkMyF+Alinu4CEoVKD
VGhA3sk1ufMpbW8pvw4X0dFIITFIQeift3DBCemxw23rBc2FqjkaDi3EszINO22/
eUTHyjvcxfCFFPi7aHsNnhJyJm7lY9Kegudmg/Ij93zGE7d5darVBuHvpQKBgBBY
YovUgFMLR1UfPeD2zUKy52I4BKrJFemxBNtOKw3mPSIcTfPoFymcMTVENs+eARoq
svlZK1uAo8ni3e+Pqd3cQrOyhHQFPxwwrdH+amGJemp7vOV4erDZH7l3Q/S27Fhw
bI1nSIKFGukBupB58wRxLiyha9C0QqmYC0/pRg5JAn8Rbj5tP26oVCXjZEfWJL8J
axxSxsGA4Vol6i6LYnVgZG+1ez2rP8vUORo1lRzmdeP4o1BSJf9TPwXkuppE5J+t
UZVKtYGlEn1RqwGNd8I9TiWvU84rcY9nsxlDR86xwKRWFvYqVOiGYtzRyewYRdjU
rTs9aqB3v1+OVxGxR6Na
-----END PRIVATE KEY-----
";

#[allow(dead_code)]
const OIDC_SIGNATURE_KEY_ES256: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggybcqc86ulFFiOon
WiYrLO4z8/kmkqvA7wGElBok9IqhRANCAAQxZK68FnQtHC0eyh8CA05xRIvxhVHn
0ymka6XBh9aFtW4wfeoKhTkSKjHc/zjh9Rr2dr3kvmYe80fMGhW4ycGA
-----END PRIVATE KEY-----
";
