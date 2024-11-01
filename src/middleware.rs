use actix_web::{
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use serde_json::json;
use std::future::{ready, Ready};

// Middleware for checking login status
pub struct CheckLogin;

impl<S> Transform<S, ServiceRequest> for CheckLogin
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = CheckLoginMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CheckLoginMiddleware { service }))
    }
}

pub struct CheckLoginMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for CheckLoginMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        // Get the path of the incoming request
        let path = request.uri().path();

        // Skip authentication check for allowed paths
        if path == "/users/register" || path == "/login_user" || path == "/users/{id}"
        || path == "/login" || path == "/users/forgot_password" || path == "/verify_otp"  {
            return Box::pin(self.service.call(request));
        }

        // Check for the token in the Authorization header
        if let Some(auth_header) = request.headers().get("Authorization") {
            if let Ok(token_str) = auth_header.to_str() {
                // Log the received token for debugging
                eprintln!("Received Authorization header: {}", token_str);

                // Check if the token starts with "Bearer " and is non-empty
                if token_str.starts_with("Bearer ") {
                    let token = &token_str[7..]; // Remove "Bearer " prefix

                    if !token.is_empty() {
                        // Token exists, allow the request to proceed
                        return Box::pin(self.service.call(request));
                    }
                }
            }
        }

        // No valid token found, respond with Unauthorized
        eprintln!("Unauthorized access attempt for path: {}", path);
        let response = HttpResponse::Unauthorized().json(json!({
            "status": "Unauthorized",
            "info": "Please login first"
        }));

        // Create the ServiceResponse and return it as a future
        let (request, _pl) = request.into_parts();
        Box::pin(async { Ok(ServiceResponse::new(request, response)) })
    }
}