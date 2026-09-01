use axum::http::StatusCode;
use axum::response::IntoResponse;
use criterion::{criterion_group, criterion_main, Criterion};
use barbican::{AuthRejection, is_public_path};

fn bench_auth_rejection_missing_credentials(c: &mut Criterion) {
    c.bench_function("auth_rejection_missing_credentials", |b| {
        b.iter(|| AuthRejection::MissingCredentials);
    });
}

fn bench_auth_rejection_invalid_token(c: &mut Criterion) {
    c.bench_function("auth_rejection_invalid_token", |b| {
        b.iter(|| AuthRejection::InvalidToken("eyJhbGciOiJIUzI1NiJ9.invalid".into()));
    });
}

fn bench_auth_rejection_insufficient_permissions(c: &mut Criterion) {
    c.bench_function("auth_rejection_insufficient_permissions", |b| {
        b.iter(|| AuthRejection::InsufficientPermissions("admin:write".into()));
    });
}

fn bench_auth_rejection_into_response(c: &mut Criterion) {
    c.bench_function("auth_rejection_into_response", |b| {
        b.iter(|| {
            let rejection = AuthRejection::InvalidToken("bad-token".into());
            let response = rejection.into_response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
    });
}

fn bench_is_public_path_match(c: &mut Criterion) {
    let prefixes = &["/health", "/metrics", "/api/docs", "/public"];
    c.bench_function("is_public_path_match", |b| {
        b.iter(|| is_public_path("/health", prefixes));
    });
}

fn bench_is_public_path_no_match(c: &mut Criterion) {
    let prefixes = &["/health", "/metrics", "/api/docs", "/public"];
    c.bench_function("is_public_path_no_match", |b| {
        b.iter(|| is_public_path("/api/users/123", prefixes));
    });
}

fn bench_is_public_path_long_path(c: &mut Criterion) {
    let prefixes = &["/health", "/metrics", "/api/docs", "/public", "/static", "/assets"];
    let long_path = "/api/v1/very/deeply/nested/resource/with/many/segments";
    c.bench_function("is_public_path_long_path", |b| {
        b.iter(|| is_public_path(long_path, prefixes));
    });
}

criterion_group!(
    benches,
    bench_auth_rejection_missing_credentials,
    bench_auth_rejection_invalid_token,
    bench_auth_rejection_insufficient_permissions,
    bench_auth_rejection_into_response,
    bench_is_public_path_match,
    bench_is_public_path_no_match,
    bench_is_public_path_long_path,
);
criterion_main!(benches);
