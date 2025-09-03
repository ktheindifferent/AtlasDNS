use std::sync::Arc;
use std::fs;
use std::io::Read;



use handlebars::Handlebars;
use tiny_http::{Method, Request, Response, ResponseBox, Server, SslConfig as TinyHttpSslConfig};


use crate::dns::context::ServerContext;
use crate::dns::acme::AcmeCertificateManager;
use crate::dns::metrics::MetricsCollector;
use crate::dns::logging::{CorrelationContext, HttpRequestLog};
use crate::dns::doh::{DohServer, DohConfig};
use crate::web::graphql::{create_schema, graphql_playground};
use crate::web::{
    activity::ActivityLogger,
    authority, cache, index,
    users::{UserManager, LoginRequest, CreateUserRequest, UpdateUserRequest, UserRole},
    sessions::{SessionMiddleware, create_session_cookie, clear_session_cookie},
    util::{parse_formdata, FormDataDecodable},
    Result, WebError,
};

trait MediaType {
    fn json_input(&self) -> bool;
    fn json_output(&self) -> bool;
}

impl MediaType for Request {
    fn json_input(&self) -> bool {
        self.headers()
            .iter()
            .find(|x| x.field.as_str().to_ascii_lowercase() == "content-type")
            .map(|x| {
                let value: String = x.value.clone().into();
                value.contains("application/json")
            })
            .unwrap_or_default()
    }

    fn json_output(&self) -> bool {
        self.headers()
            .iter()
            .find(|x| x.field.as_str().to_ascii_lowercase() == "accept")
            .map(|x| {
                let value: String = x.value.clone().into();
                value.contains("application/json")
            })
            .unwrap_or_default()
    }
}


pub struct WebServer<'a> {
    pub context: Arc<ServerContext>,
    pub handlebars: Handlebars<'a>,
    pub user_manager: Arc<UserManager>,
    pub session_middleware: Arc<SessionMiddleware>,
    pub metrics_collector: Arc<MetricsCollector>,
    pub activity_logger: Arc<ActivityLogger>,
    pub graphql_schema: async_graphql::Schema<crate::web::graphql::QueryRoot, crate::web::graphql::MutationRoot, crate::web::graphql::SubscriptionRoot>,
    pub doh_server: Arc<DohServer>,
    pub ssl_enabled: bool,
}

impl<'a> WebServer<'a> {
    pub fn new(context: Arc<ServerContext>) -> WebServer<'a> {
        let user_manager = Arc::new(UserManager::new());
        let session_middleware = Arc::new(SessionMiddleware::new(user_manager.clone()));
        let metrics_collector = Arc::new(MetricsCollector::new());
        let activity_logger = Arc::new(ActivityLogger::new(1000)); // Keep last 1000 activities
        
        let mut handlebars = Handlebars::new();
        
        // Register the 'eq' helper for comparing values in templates
        handlebars.register_helper(
            "eq",
            Box::new(|h: &handlebars::Helper, _r: &Handlebars, _ctx: &handlebars::Context, _rc: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let param1 = h.param(0).and_then(|v| v.value().as_str());
                let param2 = h.param(1).and_then(|v| v.value().as_str());
                
                // Simple inline helper - just output true/false for use in {{#if}}
                if param1 == param2 {
                    out.write("true")?;
                }
                Ok(())
            })
        );
        
        // Register the 'substring' helper for string manipulation
        handlebars.register_helper(
            "substring",
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                if let Some(text) = h.param(0).and_then(|v| v.value().as_str()) {
                    let start = h.param(1).and_then(|v| v.value().as_u64()).unwrap_or(0) as usize;
                    let end = h.param(2).and_then(|v| v.value().as_u64()).unwrap_or(text.len() as u64) as usize;
                    
                    if start < text.len() {
                        let end = end.min(text.len());
                        out.write(&text[start..end])?;
                    }
                }
                Ok(())
            })
        );
        
        // Register the 'contains' helper for string containment checks
        handlebars.register_helper(
            "contains",
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let haystack = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
                let needle = h.param(1).and_then(|v| v.value().as_str()).unwrap_or("");
                
                if haystack.contains(needle) {
                    out.write("true")?;
                }
                Ok(())
            })
        );
        
        // Register the 'gt' helper for greater than comparisons
        handlebars.register_helper(
            "gt",
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let param1 = h.param(0).and_then(|v| v.value().as_f64()).unwrap_or(0.0);
                let param2 = h.param(1).and_then(|v| v.value().as_f64()).unwrap_or(0.0);
                
                if param1 > param2 {
                    out.write("true")?;
                }
                Ok(())
            })
        );
        
        let graphql_schema = create_schema(context.clone());
        
        // Create DoH server with default config
        let doh_config = DohConfig {
            enabled: true,
            port: 443,
            path: "/dns-query".to_string(),
            max_message_size: 4096,
            http2: true,
            cors: true,
            cache_max_age: 300,
        };
        let doh_server = Arc::new(DohServer::new(context.clone(), doh_config));
        
        let mut server = WebServer {
            context,
            handlebars,
            user_manager,
            session_middleware,
            metrics_collector,
            activity_logger,
            graphql_schema,
            doh_server,
            ssl_enabled: false,
        };

        let mut register_template = |name, data: &str| {
            if server
                .handlebars
                .register_template_string(name, data).is_err()
            {
                log::info!("Failed to register template {}", name);
            }
        };

        register_template("layout", include_str!("templates/layout.html"));
        register_template("authority", include_str!("templates/authority.html"));
        register_template("cache", include_str!("templates/cache.html"));
        register_template("zone", include_str!("templates/zone.html"));
        register_template("index", include_str!("templates/index.html"));
        register_template("login", include_str!("templates/login.html"));
        register_template("users", include_str!("templates/users.html"));
        register_template("sessions", include_str!("templates/sessions.html"));
        register_template("profile", include_str!("templates/profile.html"));
        
        // Register new templates
        register_template("analytics", include_str!("templates/analytics.html"));
        register_template("dnssec", include_str!("templates/dnssec.html"));
        register_template("firewall", include_str!("templates/firewall.html"));
        register_template("rate_limiting", include_str!("templates/rate_limiting.html"));
        register_template("ddos_protection", include_str!("templates/ddos_protection.html"));
        register_template("doh", include_str!("templates/doh.html"));
        register_template("dot", include_str!("templates/dot.html"));
        register_template("doq", include_str!("templates/doq.html"));
        register_template("load_balancing", include_str!("templates/load_balancing.html"));
        register_template("geodns", include_str!("templates/geodns.html"));
        register_template("traffic_steering", include_str!("templates/traffic_steering.html"));
        register_template("health_checks", include_str!("templates/health_checks.html"));
        register_template("logs", include_str!("templates/logs.html"));
        register_template("alerts", include_str!("templates/alerts.html"));
        register_template("api", include_str!("templates/api.html"));
        register_template("webhooks", include_str!("templates/webhooks.html"));
        register_template("certificates", include_str!("templates/certificates.html"));
        register_template("templates", include_str!("templates/templates.html"));
        register_template("settings", include_str!("templates/settings.html"));

        server
    }

    /// Safely create an HTTP header, returning a default on error
    fn safe_header(header_str: &str) -> tiny_http::Header {
        header_str.parse().unwrap_or_else(|_| {
            log::warn!("Failed to parse header: {}", header_str);
            "Content-Type: text/plain".parse().expect("Default header should always parse")
        })
    }

    /// Safely create a location header
    fn safe_location_header(location: &str) -> tiny_http::Header {
        format!("Location: {}", location).parse().unwrap_or_else(|_| {
            log::warn!("Failed to parse location header: {}", location);
            "Location: /".parse().expect("Default location header should always parse")
        })
    }

    /// Safely serialize JSON, returning error JSON on failure
    fn safe_json_string<T: serde::Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap_or_else(|e| {
            log::warn!("Failed to serialize JSON: {}", e);
            "{\"error\": \"Serialization failed\"}".to_string()
        })
    }

    /// Route an HTTP request to the appropriate handler
    fn route_request(
        &self,
        request: &mut tiny_http::Request,
    ) -> Result<Response<Box<dyn std::io::Read + Send + 'static>>> {
        let url = request.url().to_string();
        let method = request.method();
        let url_parts: Vec<&str> = url.split("/").filter(|x| !x.is_empty()).collect();

        // Public routes that don't require authentication
        let is_public_route = matches!(
            (method, url_parts.as_slice()),
            (Method::Get, ["auth", "login"]) |
            (Method::Post, ["auth", "login"]) |
            (Method::Get, ["dns-query"]) |
            (Method::Post, ["dns-query"]) |
            (Method::Get, ["api", "version"])
        );

        // Check authentication for protected routes
        if !is_public_route {
            // Check if user has a valid session
            if let Err(_) = self.session_middleware.validate_request(request) {
                // For API requests, return 401
                if request.json_output() {
                    return Ok(Response::from_string("{\"error\": \"Unauthorized\"}")
                        .with_status_code(401)
                        .with_header(Self::safe_header("Content-Type: application/json"))
                        .boxed());
                }
                // For web requests, redirect to login
                return Ok(Response::empty(302)
                    .with_header(Self::safe_location_header("/auth/login"))
                    .boxed());
            }
        }

        match (method, url_parts.as_slice()) {
            (Method::Post, ["auth", "login"]) => self.login(request),
            (Method::Post, ["auth", "logout"]) => self.logout(request),
            (Method::Get, ["auth", "login"]) => self.login_page(request),
            
            (Method::Post, ["users"]) => self.create_user(request),
            (Method::Get, ["users"]) => self.list_users(request),
            (Method::Get, ["users", user_id]) => self.get_user_details(request, user_id),
            (Method::Put, ["users", user_id]) => self.update_user(request, user_id),
            (Method::Delete, ["users", user_id]) => self.delete_user(request, user_id),
            
            (Method::Get, ["sessions"]) => self.list_sessions(request),
            (Method::Delete, ["sessions", session_id]) => self.revoke_session(request, session_id),
            
            (Method::Get, ["profile"]) => self.user_profile(request),
            (Method::Put, ["profile"]) => self.update_profile(request),
            
            (Method::Post, ["authority", zone]) => self.record_create(request, zone),
            (Method::Delete, ["authority", zone]) => self.record_delete(request, zone),
            (Method::Post, ["authority", zone, "delete_record"]) => self.record_delete(request, zone),
            (Method::Get, ["authority", zone]) => self.zone_view(request, zone),
            (Method::Post, ["authority"]) => self.zone_create(request),
            (Method::Get, ["authority"]) => self.zone_list(request),
            (Method::Get, ["cache"]) => self.cacheinfo(request),
            (Method::Get, ["metrics"]) => self.metrics(request),
            (Method::Get, ["graphql"]) => self.graphql_playground(request),
            (Method::Post, ["graphql"]) => self.graphql_handler(request),
            (Method::Get, ["dns-query"]) => self.doh_handler(request),
            (Method::Post, ["dns-query"]) => self.doh_handler(request),
            (Method::Get, ["api", "version"]) => self.version_handler(request),
            
            // New UI routes
            (Method::Get, ["analytics"]) => self.analytics_page(request),
            (Method::Get, ["dnssec"]) => self.dnssec_page(request),
            (Method::Get, ["firewall"]) => self.firewall_page(request),
            (Method::Post, ["api", "firewall", "rules"]) => self.add_firewall_rule(request),
            (Method::Delete, ["api", "firewall", "rules", rule_id]) => self.delete_firewall_rule(request, rule_id),
            (Method::Post, ["api", "firewall", "blocklist"]) => self.load_blocklist(request),
            (Method::Post, ["api", "firewall", "allowlist"]) => self.load_allowlist(request),
            (Method::Get, ["templates"]) => self.templates_page(request),
            (Method::Get, ["rate-limiting"]) => self.rate_limiting_page(request),
            (Method::Post, ["api", "rate-limiting", "unblock", client_ip]) => self.unblock_client(request, client_ip),
            (Method::Get, ["api", "security", "metrics"]) => self.get_security_metrics(request),
            (Method::Get, ["api", "security", "alerts"]) => self.get_security_alerts(request),
            (Method::Get, ["api", "security", "events"]) => self.get_security_events(request),
            (Method::Get, ["ddos-protection"]) => self.ddos_protection_page(request),
            (Method::Get, ["protocols", "doh"]) => self.doh_page(request),
            (Method::Get, ["protocols", "dot"]) => self.dot_page(request),
            (Method::Get, ["protocols", "doq"]) => self.doq_page(request),
            (Method::Get, ["load-balancing"]) => self.load_balancing_page(request),
            (Method::Get, ["geodns"]) => self.geodns_page(request),
            (Method::Get, ["traffic-steering"]) => self.traffic_steering_page(request),
            (Method::Get, ["health-checks"]) => self.health_checks_page(request),
            (Method::Get, ["logs"]) => self.logs_page(request),
            (Method::Get, ["alerts"]) => self.alerts_page(request),
            (Method::Get, ["api"]) => self.api_page(request),
            (Method::Get, ["webhooks"]) => self.webhooks_page(request),
            (Method::Get, ["certificates"]) => self.certificates_page(request),
            (Method::Get, ["settings"]) => self.settings_page(request),
            
            (Method::Get, []) => self.index(request),
            (_, _) => self.not_found(request),
        }
    }

    /// Handle a single HTTP request
    fn handle_request(&self, mut request: tiny_http::Request) {
        // Create correlation context for this HTTP request
        let mut ctx = CorrelationContext::new("web_server", "handle_request");
        
        let method = format!("{:?}", request.method());
        let path = request.url().to_string();
        
        // Extract headers we need
        let user_agent = request.headers()
            .iter()
            .find(|h| h.field.as_str() == "User-Agent")
            .map(|h| h.value.as_str())
            .unwrap_or("Unknown")
            .to_string();
        
        let referer = request.headers()
            .iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "referer")
            .map(|h| h.value.as_str().to_string());
        
        // Calculate request size
        let request_size = self.calculate_request_size(&request);
        
        ctx = ctx.with_metadata("method", &method)
               .with_metadata("path", &path)
               .with_metadata("user_agent", &user_agent);

        let response = self.route_request(&mut request);
        
        // Extract status code from response
        let status_code = match &response {
            Ok(_) => 200, // Default success
            Err(WebError::AuthenticationError(_)) => 401,
            Err(WebError::AuthorizationError(_)) => 403,
            Err(WebError::UserNotFound) | Err(WebError::ZoneNotFound) => 404,
            Err(_) => 500,
        };
        
        // Calculate response size and send response
        let (response_size, response_result) = self.send_response_with_size(request, response);
        
        // Log the HTTP request with sizes
        let request_log = HttpRequestLog {
            method: method.clone(),
            path: path.clone(),
            status_code,
            request_size: Some(request_size),
            response_size,
            user_agent: Some(user_agent.clone()),
            referer,
        };
        self.context.logger.log_http_request(&ctx, request_log);
        
        // Record metrics
        self.context.metrics.record_web_request(&method, &path, &status_code.to_string());
        self.context.metrics.record_web_duration(&method, &path, ctx.elapsed());
        
        // Record size metrics
        if let Some(resp_size) = response_size {
            self.context.metrics.record_web_response_size(&method, &path, resp_size);
        }
        self.context.metrics.record_web_request_size(&method, &path, request_size);

        if let Err(err) = response_result {
            log::error!("Failed to write response to client: {:?}", err);
            self.context.metrics.record_error("web_server", "response_write_failed");
        }
    }

    /// Calculate the size of an HTTP request in bytes
    fn calculate_request_size(&self, request: &tiny_http::Request) -> u64 {
        let mut size = 0u64;
        
        // Request line size (method + path + HTTP version)
        let request_line = format!("{} {} HTTP/1.1\r\n", request.method(), request.url());
        size += request_line.len() as u64;
        
        // Headers size
        for header in request.headers() {
            // Each header: "Name: Value\r\n"
            let field = header.field.to_string();
            let value = header.value.to_string();
            size += field.len() as u64;
            size += 2; // ": "
            size += value.len() as u64;
            size += 2; // "\r\n"
        }
        
        // Empty line after headers
        size += 2; // "\r\n"
        
        // Body size (if present)
        // Check Content-Length header for body size
        if let Some(content_length) = request.headers()
            .iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "content-length")
            .and_then(|h| h.value.as_str().parse::<u64>().ok()) {
            size += content_length;
        }
        
        size
    }
    
    /// Send the response back to the client with proper error handling and size calculation
    fn send_response_with_size(
        &self,
        request: tiny_http::Request,
        response: Result<ResponseBox>,
    ) -> (Option<u64>, std::io::Result<()>) {
        match response {
            Ok(response) => {
                // Try to get Content-Length if available in headers
                // Otherwise use a reasonable estimate
                let estimated_size = self.estimate_response_box_size(&response);
                (Some(estimated_size), request.respond(response))
            }
            Err(err) if request.json_output() => {
                log::info!("Request failed: {:?}", err);
                
                // Report error to Sentry with request context
                sentry::configure_scope(|scope| {
                    scope.set_tag("request_type", "json");
                    scope.set_tag("method", request.method().as_str());
                    scope.set_tag("path", request.url());
                    if let Some(content_length) = request.body_length() {
                        scope.set_extra("content_length", content_length.into());
                    }
                });
                err.report_to_sentry();
                
                let error_json = serde_json::json!({
                    "message": err.to_string(),
                });
                let error_string = Self::safe_json_string(&error_json);
                let size = self.calculate_response_string_size(&error_string, self.error_status_code(&err));
                let response = Response::from_string(error_string)
                    .with_header(Self::safe_header("Content-Type: application/json"));
                (Some(size), request.respond(response))
            }
            Err(err) => {
                log::info!("Request failed: {:?}", err);
                
                // Report error to Sentry with request context
                sentry::configure_scope(|scope| {
                    scope.set_tag("request_type", "html");
                    scope.set_tag("method", request.method().as_str());
                    scope.set_tag("path", request.url());
                    if let Some(content_length) = request.body_length() {
                        scope.set_extra("content_length", content_length.into());
                    }
                });
                err.report_to_sentry();
                
                let error_string = err.to_string();
                let size = self.calculate_response_string_size(&error_string, self.error_status_code(&err));
                let response = Response::from_string(error_string)
                    .with_header(Self::safe_header("Content-Type: text/plain"));
                (Some(size), request.respond(response))
            }
        }
    }
    
    /// Estimate the size of a ResponseBox
    fn estimate_response_box_size(&self, _response: &ResponseBox) -> u64 {
        // Since we can't easily introspect the ResponseBox,
        // we'll use heuristics based on typical response sizes
        // This could be improved by tracking sizes at response creation time
        
        // Basic estimate: status line + headers + typical content
        let status_line = 20u64; // "HTTP/1.1 200 OK\r\n"
        let headers = 200u64; // Typical headers size
        let content = 2000u64; // Default content estimate
        
        status_line + headers + content
    }
    
    /// Get status code for error
    fn error_status_code(&self, err: &WebError) -> u16 {
        match err {
            WebError::AuthenticationError(_) => 401,
            WebError::AuthorizationError(_) => 403,
            WebError::UserNotFound | WebError::ZoneNotFound => 404,
            _ => 500,
        }
    }
    
    /// Calculate the size of a string response
    fn calculate_response_string_size(&self, content: &str, status_code: u16) -> u64 {
        let mut size = 0u64;
        
        // Status line (e.g., "HTTP/1.1 200 OK\r\n")
        let status_text = match status_code {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };
        let status_line = format!("HTTP/1.1 {} {}\r\n", status_code, status_text);
        size += status_line.len() as u64;
        
        // Basic headers (estimate)
        // Content-Type, Content-Length, Date, Server, etc.
        size += 150; // Approximate headers size
        
        // Empty line after headers
        size += 2; // "\r\n"
        
        // Content
        size += content.len() as u64;
        
        size
    }
    
    /// Send the response back to the client with proper error handling
    fn send_response(
        &self,
        request: tiny_http::Request,
        response: Result<Response<Box<dyn std::io::Read + Send + 'static>>>,
    ) -> std::io::Result<()> {
        match response {
            Ok(response) => request.respond(response),
            Err(err) if request.json_output() => {
                log::info!("Request failed: {:?}", err);
                let error_json = serde_json::json!({
                    "message": err.to_string(),
                });
                let error_string = Self::safe_json_string(&error_json);
                request.respond(Response::from_string(error_string))
            }
            Err(err) => {
                log::info!("Request failed: {:?}", err);
                request.respond(Response::from_string(err.to_string()))
            }
        }
    }

    pub fn run_webserver(mut self, use_ssl: bool) {
        self.ssl_enabled = use_ssl && self.context.ssl_config.enabled;
        if self.ssl_enabled {
            self.run_ssl_webserver();
        } else {
            self.run_http_webserver();
        }
    }
    
    fn run_http_webserver(&self) {
        let webserver = match Server::http(("0.0.0.0", self.context.api_port)) {
            Ok(x) => x,
            Err(e) => {
                log::info!("Failed to start HTTP web server: {:?}", e);
                return;
            }
        };

        log::info!(
            "HTTP web server started and listening on port {}",
            self.context.api_port
        );

        for request in webserver.incoming_requests() {
            self.handle_request(request);
        }
    }
    
    fn run_ssl_webserver(&self) {
        // Check if we need to obtain/renew certificates via ACME
        if let Some(ref acme_config) = self.context.ssl_config.acme {
            let mut cert_manager = match AcmeCertificateManager::new(
                acme_config.clone(),
                self.context.clone()
            ) {
                Ok(manager) => manager,
                Err(e) => {
                    log::error!("Failed to create ACME certificate manager: {:?}", e);
                    log::info!("Falling back to HTTP server");
                    self.run_http_webserver();
                    return;
                }
            };
            
            if cert_manager.needs_renewal() {
                log::info!("Obtaining/renewing SSL certificate via ACME...");
                if let Err(e) = cert_manager.obtain_certificate() {
                    log::error!("Failed to obtain certificate: {:?}", e);
                    log::info!("Falling back to HTTP server");
                    self.run_http_webserver();
                    return;
                }
            }
        }
        
        // Determine certificate and key paths
        let (cert_path, key_path) = if let Some(ref acme_config) = self.context.ssl_config.acme {
            (acme_config.cert_path.clone(), acme_config.key_path.clone())
        } else if let (Some(cert), Some(key)) = (
            self.context.ssl_config.cert_path.clone(),
            self.context.ssl_config.key_path.clone()
        ) {
            (cert, key)
        } else {
            log::error!("SSL enabled but no certificate configuration provided");
            log::info!("Falling back to HTTP server");
            self.run_http_webserver();
            return;
        };
        
        // Verify certificate files exist
        if !cert_path.exists() || !key_path.exists() {
            log::error!("Certificate or key file not found");
            log::info!("Falling back to HTTP server");
            self.run_http_webserver();
            return;
        }
        
        // Create SSL configuration by reading the files
        let cert_data = match fs::read(&cert_path) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to read certificate file: {:?}", e);
                log::info!("Falling back to HTTP server");
                self.run_http_webserver();
                return;
            }
        };
        
        let key_data = match fs::read(&key_path) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to read key file: {:?}", e);
                log::info!("Falling back to HTTP server");
                self.run_http_webserver();
                return;
            }
        };
        
        let ssl_config = TinyHttpSslConfig {
            certificate: cert_data,
            private_key: key_data,
        };
        
        // Start HTTPS server
        let webserver = match Server::https(
            ("0.0.0.0", self.context.ssl_config.port),
            ssl_config
        ) {
            Ok(x) => x,
            Err(e) => {
                log::error!("Failed to start HTTPS web server: {:?}", e);
                log::info!("Falling back to HTTP server");
                self.run_http_webserver();
                return;
            }
        };

        log::info!(
            "HTTPS web server started and listening on port {}",
            self.context.ssl_config.port
        );

        // Also start HTTP server for redirect if configured
        if self.context.api_port != self.context.ssl_config.port {
            std::thread::spawn({
                let context = self.context.clone();
                move || {
                    if let Ok(http_server) = Server::http(("0.0.0.0", context.api_port)) {
                        log::info!("HTTP redirect server started on port {}", context.api_port);
                        for request in http_server.incoming_requests() {
                            let url = request.url();
                            let host = request.headers()
                                .iter()
                                .find(|h| h.field.as_str() == "Host")
                                .map(|h| h.value.as_str())
                                .unwrap_or("localhost");
                            
                            let redirect_url = format!("https://{}:{}{}", 
                                host.split(':').next().unwrap_or(host),
                                context.ssl_config.port,
                                url
                            );
                            
                            let response = Response::empty(301)
                                .with_header(Self::safe_location_header(&redirect_url));
                            
                            let _ = request.respond(response);
                        }
                    }
                }
            });
        }

        for request in webserver.incoming_requests() {
            self.handle_request(request);
        }
    }



    fn response_from_media_type<R>(
        &self,
        request: &Request,
        template: &str,
        data: R,
    ) -> Result<ResponseBox>
    where
        R: serde::Serialize,
    {
        if request.json_output() {
            let json_string = serde_json::to_string(&data)?;
            Ok(Response::from_string(json_string)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            let html_string = self.handlebars.render(template, &data)?;
            Ok(Response::from_string(html_string)
                .with_header::<tiny_http::Header>(Self::safe_header("Content-Type: text/html"))
                .boxed())
        }
    }

    fn add_user_context(&self, request: &Request, data: &mut serde_json::Value) -> Result<()> {
        // Try to get user session data
        if let Ok((_, user)) = self.session_middleware.validate_request(request) {
            if let Some(obj) = data.as_object_mut() {
                obj.insert("username".to_string(), serde_json::json!(user.username));
                obj.insert("role".to_string(), serde_json::json!(user.role));
                obj.insert("user_id".to_string(), serde_json::json!(user.id));
            }
        }
        Ok(())
    }

    fn index(&self, request: &Request) -> Result<ResponseBox> {
        let mut index_result = index::index(&self.context, &self.user_manager, &self.activity_logger)?;
        self.add_user_context(request, &mut index_result)?;
        self.response_from_media_type(request, "index", index_result)
    }

    fn zone_list(&self, request: &Request) -> Result<ResponseBox> {
        let mut zone_list_result = authority::zone_list(&self.context)?;
        self.add_user_context(request, &mut zone_list_result)?;
        self.response_from_media_type(request, "authority", zone_list_result)
    }

    fn zone_view(&self, request: &Request, zone: &str) -> Result<ResponseBox> {
        let mut zone_view_result = authority::zone_view(&self.context, zone)?;
        self.add_user_context(request, &mut zone_view_result)?;
        self.response_from_media_type(request, "zone", zone_view_result)
    }

    fn zone_create(&self, request: &mut Request) -> Result<ResponseBox> {
        let zone_create_request = if request.json_input() {
            serde_json::from_reader(request.as_reader())?
        } else {
            parse_formdata(&mut request.as_reader())
                .and_then(authority::ZoneCreateRequest::from_formdata)?
        };

        let zone = authority::zone_create(&self.context, zone_create_request)?;

        Ok(
            Response::empty(if request.json_output() { 201 } else { 302 })
                .with_header::<tiny_http::Header>(Self::safe_location_header(&format!("/authority/{}", zone.domain)))
                .boxed(),
        )
    }

    fn record_create(&self, request: &mut Request, zone: &str) -> Result<ResponseBox> {
        let record_request = if request.json_input() {
            serde_json::from_reader(request.as_reader())?
        } else {
            parse_formdata(&mut request.as_reader())
                .and_then(authority::RecordRequest::from_formdata)?
        };

        authority::record_create(&self.context, zone, record_request)?;

        Ok(
            Response::empty(if request.json_output() { 201 } else { 302 })
                .with_header::<tiny_http::Header>(Self::safe_location_header(&format!("/authority/{}", zone)))
                .boxed(),
        )
    }

    fn record_delete(&self, request: &mut Request, zone: &str) -> Result<ResponseBox> {
        let record_request = if request.json_input() {
            serde_json::from_reader(request.as_reader())?
        } else {
            parse_formdata(&mut request.as_reader())
                .and_then(authority::RecordRequest::from_formdata)?
        };

        authority::record_delete(&self.context, zone, record_request)?;

        Ok(
            Response::empty(if request.json_output() { 201 } else { 302 })
                .with_header::<tiny_http::Header>(Self::safe_location_header(&format!("/authority/{}", zone)))
                .boxed(),
        )
    }

    fn cacheinfo(&self, request: &Request) -> Result<ResponseBox> {
        let cacheinfo_result = cache::cacheinfo(&self.context)?;
        let mut data = serde_json::to_value(cacheinfo_result)?;
        self.add_user_context(request, &mut data)?;
        self.response_from_media_type(request, "cache", data)
    }

    fn metrics(&self, _request: &Request) -> Result<ResponseBox> {
        // Update metrics before exporting
        self.update_current_metrics();
        
        let metrics_output = self.metrics_collector.export_metrics()
            .map_err(|e| WebError::InternalError(format!("Failed to export metrics: {}", e)))?;
        
        Ok(Response::from_string(metrics_output)
            .with_header::<tiny_http::Header>(Self::safe_header("Content-Type: text/plain; version=0.0.4; charset=utf-8"))
            .boxed())
    }

    fn update_current_metrics(&self) {
        // Update zone statistics
        if let Ok(zones) = self.context.authority.read() {
            let total_zones = zones.zones().len() as i64;
            let total_records: i64 = zones.zones().iter()
                .map(|zone| zone.records.len() as i64)
                .sum();
            
            self.metrics_collector.update_zone_stats("total_zones", total_zones);
            self.metrics_collector.update_zone_stats("total_records", total_records);
        }

        // Update cache statistics
        if let Ok(cache_list) = self.context.cache.list() {
            self.metrics_collector.update_cache_size("response", cache_list.len() as i64);
        }

        // Update user session statistics
        let sessions = self.user_manager.list_sessions(None).unwrap_or_default();
        let mut admin_sessions = 0i64;
        let mut user_sessions = 0i64;
        let mut readonly_sessions = 0i64;

        for session in sessions {
            if let Ok(user) = self.user_manager.get_user(&session.user_id) {
                match user.role.as_str() {
                    "Admin" => admin_sessions += 1,
                    "User" => user_sessions += 1,
                    "ReadOnly" => readonly_sessions += 1,
                    _ => {}
                }
            }
        }

        self.metrics_collector.update_user_sessions("admin", admin_sessions);
        self.metrics_collector.update_user_sessions("user", user_sessions);
        self.metrics_collector.update_user_sessions("readonly", readonly_sessions);
    }

    fn not_found(&self, _request: &Request) -> Result<ResponseBox> {
        Ok(Response::from_string("Not found")
            .with_status_code(404)
            .boxed())
    }
    
    fn login_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "Login",
        });
        self.response_from_media_type(request, "login", data)
    }
    
    fn login(&self, request: &mut Request) -> Result<ResponseBox> {
        let login_request: LoginRequest = if request.json_input() {
            match serde_json::from_reader(request.as_reader()) {
                Ok(req) => req,
                Err(e) => {
                    log::warn!("JSON parsing failed for login request: {}", e);
                    return Err(WebError::InvalidInput(format!("Invalid JSON format: {}", e)));
                }
            }
        } else {
            parse_formdata(&mut request.as_reader())
                .and_then(LoginRequest::from_formdata)?
        };
        
        let ip_address = self.session_middleware.get_ip_address(request);
        
        let user = match self.user_manager
            .authenticate(&login_request.username, &login_request.password) {
            Ok(u) => {
                // Log successful login
                self.activity_logger.log_login(
                    login_request.username.clone(),
                    u.id.clone(),
                    ip_address.clone(),
                    true
                );
                u
            },
            Err(e) => {
                // Log failed login
                self.activity_logger.log_login(
                    login_request.username.clone(),
                    String::new(),
                    ip_address.clone(),
                    false
                );
                return Err(WebError::AuthenticationError(e));
            }
        };
        
        let user_agent = self.session_middleware.get_user_agent(request);
        
        let session = self.user_manager
            .create_session(user.id.clone(), ip_address, user_agent)
            .map_err(|e| WebError::AuthenticationError(e))?;
        
        if request.json_output() {
            let response_data = serde_json::json!({
                "token": session.token,
                "user": user,
                "expires_at": session.expires_at,
            });
            Ok(Response::from_string(serde_json::to_string(&response_data)?)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            let cookie_header = create_session_cookie(&session.token, self.ssl_enabled);
            log::debug!("Setting session cookie: {} = {}", cookie_header.field, cookie_header.value);
            log::debug!("Session token being set: {}", session.token);
            Ok(Response::empty(302)
                .with_header(cookie_header)
                .with_header(Self::safe_location_header("/"))
                .boxed())
        }
    }
    
    fn logout(&self, request: &mut Request) -> Result<ResponseBox> {
        if let Some(token) = self.session_middleware.extract_token(request) {
            let _ = self.user_manager.invalidate_session(&token);
        }
        
        if request.json_output() {
            Ok(Response::from_string("{\"success\":true}")
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            Ok(Response::empty(302)
                .with_header(clear_session_cookie())
                .with_header(Self::safe_location_header("/auth/login"))
                .boxed())
        }
    }
    
    fn create_user(&self, request: &mut Request) -> Result<ResponseBox> {
        let _ = self.session_middleware
            .require_role(request, vec![UserRole::Admin])
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        let create_request: CreateUserRequest = if request.json_input() {
            serde_json::from_reader(request.as_reader())?
        } else {
            parse_formdata(&mut request.as_reader())
                .and_then(CreateUserRequest::from_formdata)?
        };
        
        let user = self.user_manager
            .create_user(create_request)
            .map_err(|_| WebError::InvalidRequest)?;
        
        if request.json_output() {
            Ok(Response::from_string(serde_json::to_string(&user)?)
                .with_status_code(201)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            Ok(Response::empty(302)
                .with_header(Self::safe_location_header("/users"))
                .boxed())
        }
    }
    
    fn list_users(&self, request: &Request) -> Result<ResponseBox> {
        let _ = self.session_middleware
            .require_auth(request)
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        let users = self.user_manager
            .list_users()
            .map_err(|_e| WebError::InvalidRequest)?;
        
        let user_count = users.len();
        let data = serde_json::json!({
            "title": "Users",
            "users": users,
            "user_count": user_count,
        });
        
        self.response_from_media_type(request, "users", data)
    }
    
    fn get_user_details(&self, request: &Request, user_id: &str) -> Result<ResponseBox> {
        let (_, current_user) = self.session_middleware
            .require_auth(request)
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        if current_user.id != user_id && current_user.role != UserRole::Admin {
            return Err(WebError::AuthorizationError("Insufficient permissions".to_string()));
        }
        
        let user = self.user_manager
            .get_user(user_id)
            .map_err(|_| WebError::UserNotFound)?;
        
        if request.json_output() {
            Ok(Response::from_string(serde_json::to_string(&user)?)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            let data = serde_json::json!({
                "title": "User Details",
                "user": user,
            });
            self.response_from_media_type(request, "profile", data)
        }
    }
    
    fn update_user(&self, request: &mut Request, user_id: &str) -> Result<ResponseBox> {
        let _ = self.session_middleware
            .require_role(request, vec![UserRole::Admin])
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        let update_request: UpdateUserRequest = serde_json::from_reader(request.as_reader())?;
        
        let user = self.user_manager
            .update_user(user_id, update_request)
            .map_err(|_e| WebError::InvalidRequest)?;
        
        Ok(Response::from_string(serde_json::to_string(&user)?)
            .with_header(Self::safe_header("Content-Type: application/json"))
            .boxed())
    }
    
    fn delete_user(&self, request: &Request, user_id: &str) -> Result<ResponseBox> {
        let _ = self.session_middleware
            .require_role(request, vec![UserRole::Admin])
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        self.user_manager
            .delete_user(user_id)
            .map_err(|_e| WebError::InvalidRequest)?;
        
        Ok(Response::empty(204).boxed())
    }
    
    fn list_sessions(&self, request: &Request) -> Result<ResponseBox> {
        let (_, user) = self.session_middleware
            .require_auth(request)
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        let user_id = if user.role == UserRole::Admin {
            None
        } else {
            Some(user.id.as_str())
        };
        
        let sessions = self.user_manager
            .list_sessions(user_id)
            .map_err(|_e| WebError::InvalidRequest)?;
        
        let session_count = sessions.len();
        let data = serde_json::json!({
            "title": "Sessions",
            "sessions": sessions,
            "session_count": session_count,
        });
        
        self.response_from_media_type(request, "sessions", data)
    }
    
    fn revoke_session(&self, request: &Request, session_token: &str) -> Result<ResponseBox> {
        let _ = self.session_middleware
            .require_auth(request)
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        self.user_manager
            .invalidate_session(session_token)
            .map_err(|_e| WebError::InvalidRequest)?;
        
        Ok(Response::empty(204).boxed())
    }
    
    fn user_profile(&self, request: &Request) -> Result<ResponseBox> {
        let (_, user) = self.session_middleware
            .require_auth(request)
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        let data = serde_json::json!({
            "title": "Profile",
            "user": user,
        });
        
        self.response_from_media_type(request, "profile", data)
    }
    
    fn update_profile(&self, request: &mut Request) -> Result<ResponseBox> {
        let (_, user) = self.session_middleware
            .require_auth(request)
            .map_err(|e| WebError::AuthorizationError(e))?;
        
        let update_request: UpdateUserRequest = serde_json::from_reader(request.as_reader())?;
        
        let limited_request = UpdateUserRequest {
            email: update_request.email,
            password: update_request.password,
            role: None,
            is_active: None,
        };
        
        let updated_user = self.user_manager
            .update_user(&user.id, limited_request)
            .map_err(|_e| WebError::InvalidRequest)?;
        
        Ok(Response::from_string(serde_json::to_string(&updated_user)?)
            .with_header(Self::safe_header("Content-Type: application/json"))
            .boxed())
    }
    
    fn graphql_playground(&self, _request: &Request) -> Result<ResponseBox> {
        Ok(Response::from_string(graphql_playground())
            .with_header::<tiny_http::Header>(Self::safe_header("Content-Type: text/html; charset=utf-8"))
            .boxed())
    }
    
    fn graphql_handler(&self, request: &mut Request) -> Result<ResponseBox> {
        // Read the GraphQL request body
        let mut body = String::new();
        request.as_reader().read_to_string(&mut body)?;
        
        // Parse the GraphQL request
        let graphql_request: async_graphql::Request = serde_json::from_str(&body)
            .map_err(|e| WebError::InvalidRequest)?;
        
        // Execute the GraphQL query synchronously using blocking
        // Since we're in a sync context, we need to use a runtime to execute async code
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| WebError::InternalError(format!("Failed to create runtime: {}", e)))?;
        
        let response = rt.block_on(async {
            self.graphql_schema.execute(graphql_request).await
        });
        
        // Serialize the response
        let response_body = serde_json::to_string(&response)
            .map_err(|e| WebError::InternalError(format!("Failed to serialize response: {}", e)))?;
        
        Ok(Response::from_string(response_body)
            .with_header(Self::safe_header("Content-Type: application/json"))
            .boxed())
    }
    
    fn doh_handler(&self, request: &mut Request) -> Result<ResponseBox> {
        // Create a runtime for async execution
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| WebError::InternalError(format!("Failed to create runtime: {}", e)))?;
        
        // Execute the DoH handler asynchronously
        let response = rt.block_on(async {
            self.doh_server.handle_doh_request(request).await
        })?;
        
        Ok(response)
    }
    
    fn version_handler(&self, _request: &mut Request) -> Result<ResponseBox> {
        // Get actual code version - use package version as primary identifier
        let package_version = env!("CARGO_PKG_VERSION");
        
        // Try to get deployment-specific version from environment variables
        // This should be set by the Docker build or deployment process
        let deployment_version = std::env::var("BUILD_VERSION")
            .or_else(|_| std::env::var("DOCKER_IMAGE_TAG"))
            .or_else(|_| std::env::var("APP_VERSION"))
            .unwrap_or_else(|_| package_version.to_string());
        
        let response_data = serde_json::json!({
            "code_version": deployment_version,
            "package_version": package_version
        });
        
        Ok(Response::from_string(serde_json::to_string(&response_data)?)
            .with_header(Self::safe_header("Content-Type: application/json"))
            .boxed())
    }
    
    // New page handlers
    fn analytics_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get real statistics from backend
        let tcp_count = self.context.statistics.get_tcp_query_count();
        let udp_count = self.context.statistics.get_udp_query_count();
        let total_queries = tcp_count + udp_count;
        
        // Get cache statistics
        let cache_size = if let Ok(cache_list) = self.context.cache.list() {
            cache_list.len()
        } else {
            0
        };
        
        // Calculate percentages for TCP/UDP
        let (tcp_percent, udp_percent) = if total_queries > 0 {
            let tcp_pct = (tcp_count as f64 / total_queries as f64 * 100.0) as u64;
            let udp_pct = (udp_count as f64 / total_queries as f64 * 100.0) as u64;
            (tcp_pct, udp_pct)
        } else {
            (0, 0)
        };
        
        // Get comprehensive metrics from the metrics collector
        let metrics_summary = self.context.metrics.get_metrics_summary();
        
        // Extract query type distribution
        let query_types = metrics_summary.query_type_distribution;
        let a_stats = query_types.get("A").cloned().unwrap_or((0, 0.0));
        let aaaa_stats = query_types.get("AAAA").cloned().unwrap_or((0, 0.0));
        let cname_stats = query_types.get("CNAME").cloned().unwrap_or((0, 0.0));
        let mx_stats = query_types.get("MX").cloned().unwrap_or((0, 0.0));
        let txt_stats = query_types.get("TXT").cloned().unwrap_or((0, 0.0));
        
        // Extract response code distribution
        let response_codes = metrics_summary.response_code_distribution;
        let noerror_stats = response_codes.get("NOERROR").cloned().unwrap_or((0, 0.0));
        let nxdomain_stats = response_codes.get("NXDOMAIN").cloned().unwrap_or((0, 0.0));
        let servfail_stats = response_codes.get("SERVFAIL").cloned().unwrap_or((0, 0.0));
        let other_count: u64 = response_codes.iter()
            .filter(|(k, _)| !matches!(k.as_str(), "NOERROR" | "NXDOMAIN" | "SERVFAIL"))
            .map(|(_, (count, _))| count)
            .sum();
        let total_responses: u64 = response_codes.values().map(|(count, _)| count).sum();
        let other_percent = if total_responses > 0 {
            (other_count as f64 / total_responses as f64) * 100.0
        } else {
            0.0
        };
        
        // Extract percentiles
        let percentiles = metrics_summary.percentiles;
        let p50 = percentiles.get("p50").copied().unwrap_or(0.0) as i64;
        let p90 = percentiles.get("p90").copied().unwrap_or(0.0) as i64;
        let p95 = percentiles.get("p95").copied().unwrap_or(0.0) as i64;
        let p99 = percentiles.get("p99").copied().unwrap_or(0.0) as i64;
        
        // Calculate average response time from percentiles (approximation)
        let avg_response_time = if p50 > 0 {
            (p50 as f64 + p90 as f64) / 2.0
        } else {
            0.0
        };
        
        // Extract protocol distribution
        let protocol_dist = metrics_summary.protocol_distribution;
        let doh_stats = protocol_dist.get("DoH").cloned().unwrap_or((0, 0.0));
        let dot_stats = protocol_dist.get("DoT").cloned().unwrap_or((0, 0.0));
        let doq_stats = protocol_dist.get("DoQ").cloned().unwrap_or((0, 0.0));
        
        let data = serde_json::json!({
            "title": "Analytics",
            "total_queries": total_queries,
            "tcp_queries": tcp_count,
            "udp_queries": udp_count,
            "cache_entries": cache_size,
            "tcp_percent": tcp_percent,
            "udp_percent": udp_percent,
            "cache_hit_rate": metrics_summary.cache_hit_rate as i64,
            "avg_response_time": avg_response_time,
            "unique_clients": metrics_summary.unique_clients,
            "noerror_count": noerror_stats.0,
            "noerror_percent": noerror_stats.1 as i64,
            "nxdomain_count": nxdomain_stats.0,
            "nxdomain_percent": nxdomain_stats.1 as i64,
            "servfail_count": servfail_stats.0,
            "servfail_percent": servfail_stats.1 as i64,
            "other_count": other_count,
            "other_percent": other_percent as i64,
            "a_count": a_stats.0,
            "a_percent": a_stats.1 as i64,
            "aaaa_count": aaaa_stats.0,
            "aaaa_percent": aaaa_stats.1 as i64,
            "cname_count": cname_stats.0,
            "cname_percent": cname_stats.1 as i64,
            "mx_count": mx_stats.0,
            "mx_percent": mx_stats.1 as i64,
            "txt_count": txt_stats.0,
            "txt_percent": txt_stats.1 as i64,
            "p50_latency": p50,
            "p90_latency": p90,
            "p95_latency": p95,
            "p99_latency": p99,
            "doh_percent": doh_stats.1 as i64,
            "dot_percent": dot_stats.1 as i64,
            "doq_percent": doq_stats.1 as i64,
        });
        self.response_from_media_type(request, "analytics", data)
    }
    
    fn dnssec_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get DNSSEC statistics from authority
        let dnssec_stats = self.context.authority.get_dnssec_stats();
        
        // Extract values from JSON
        let total_zones = dnssec_stats["total_zones"].as_u64().unwrap_or(0);
        let signed_zones = dnssec_stats["signed_zones"].as_u64().unwrap_or(0);
        let signed_percent = if total_zones > 0 {
            ((signed_zones as f64 / total_zones as f64) * 100.0) as u64
        } else {
            0
        };
        
        let data = serde_json::json!({
            "title": "DNSSEC Management",
            "total_zones": total_zones,
            "signed_zones": signed_zones,
            "signed_percent": signed_percent,
            "active_keys": dnssec_stats["keys_generated"].as_u64().unwrap_or(0),
            "ksk_count": signed_zones, // Assume one KSK per signed zone
            "zsk_count": signed_zones, // Assume one ZSK per signed zone
            "key_rollovers": dnssec_stats["key_rollovers"].as_u64().unwrap_or(0),
            "signatures_created": dnssec_stats["signatures_created"].as_u64().unwrap_or(0),
            "validation_failures": dnssec_stats["validation_failures"].as_u64().unwrap_or(0),
            "avg_signing_time_ms": dnssec_stats["avg_signing_time_ms"].as_f64().unwrap_or(0.0),
            "dnssec_enabled": self.context.dnssec_enabled,
        });
        self.response_from_media_type(request, "dnssec", data)
    }
    
    fn firewall_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get firewall metrics from security manager
        let security_metrics = self.context.security_manager.get_metrics();
        let security_stats = self.context.security_manager.get_statistics();
        
        let data = serde_json::json!({
            "title": "DNS Firewall",
            "blocked_queries": security_metrics.firewall_blocked,
            "active_rules": security_metrics.active_rules,
            "custom_rules": security_metrics.active_rules, // Same as active rules for now
            "threat_feeds": 0, // TODO: Track threat feed count
            "block_rate": if security_metrics.total_queries > 0 {
                (security_metrics.firewall_blocked as f64 / security_metrics.total_queries as f64) * 100.0
            } else {
                0.0
            },
        });
        self.response_from_media_type(request, "firewall", data)
    }
    
    fn templates_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "Zone Templates",
        });
        self.response_from_media_type(request, "templates", data)
    }
    
    fn rate_limiting_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get rate limiting metrics from security manager
        let security_metrics = self.context.security_manager.get_metrics();
        let security_stats = self.context.security_manager.get_statistics();
        
        let data = serde_json::json!({
            "title": "Rate Limiting",
            "throttled_queries": security_metrics.rate_limited,
            "blocked_clients": security_metrics.blocked_ips,
            "active_limits": security_metrics.throttled_clients,
            "avg_qps": if security_metrics.total_queries > 0 {
                security_metrics.total_queries / 60 // Assuming per minute
            } else {
                0
            },
        });
        self.response_from_media_type(request, "rate_limiting", data)
    }
    
    fn ddos_protection_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get DDoS protection metrics from security manager
        let security_metrics = self.context.security_manager.get_metrics();
        
        let threat_level_str = match security_metrics.threat_level {
            crate::dns::security::ThreatLevel::None => "None",
            crate::dns::security::ThreatLevel::Low => "Low",
            crate::dns::security::ThreatLevel::Medium => "Medium",
            crate::dns::security::ThreatLevel::High => "High",
            crate::dns::security::ThreatLevel::Critical => "Critical",
        };
        
        let data = serde_json::json!({
            "title": "DDoS Protection",
            "blocked_attacks": security_metrics.ddos_attacks_detected,
            "detection_rules": security_metrics.active_rules,
            "threat_level": threat_level_str,
            "auto_block_enabled": true, // Default enabled in our implementation
        });
        self.response_from_media_type(request, "ddos_protection", data)
    }
    
    fn doh_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get DoH configuration from server
        let doh_enabled = self.doh_server.is_enabled();
        let doh_config = self.doh_server.get_config();
        
        let data = serde_json::json!({
            "title": "DNS-over-HTTPS",
            "enabled": doh_enabled,
            "port": doh_config.port,
            "path": doh_config.path,
            "http2_enabled": doh_config.http2,
            "cors_enabled": doh_config.cors,
            "max_message_size": doh_config.max_message_size,
            "cache_max_age": doh_config.cache_max_age,
            // TODO: Add DoH query tracking to metrics
            "doh_queries": 0,
            "active_connections": 0,
            "avg_latency": 0,
            "cache_hit_rate": 0,
        });
        self.response_from_media_type(request, "doh", data)
    }
    
    fn dot_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "DNS-over-TLS",
            // TODO: Implement DoT server functionality
            "enabled": false,
            "port": 853,
            "dot_connections": 0,
            "qps": 0,
            "tls_version": "Not configured",
        });
        self.response_from_media_type(request, "dot", data)
    }
    
    fn doq_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "DNS-over-QUIC",
            // TODO: Implement DoQ server functionality
            "enabled": false,
            "port": 853,
            "quic_streams": 0,
            "zero_rtt": 0,
            "packet_loss": 0.0,
            "latency": 0,
            "http3_enabled": false,
        });
        self.response_from_media_type(request, "doq", data)
    }
    
    fn load_balancing_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "Load Balancing",
            // TODO: Implement load balancing manager
            "enabled": false,
            "active_pools": 0,
            "total_endpoints": 0,
            "requests_per_sec": 0,
            "failovers": 0,
            "health_check_interval": 30,
        });
        self.response_from_media_type(request, "load_balancing", data)
    }
    
    fn geodns_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "GeoDNS",
            // TODO: Implement GeoDNS manager
            "enabled": false,
            "regions": 0,
            "countries": 0,
            "asn_rules": 0,
            "geo_routes": 0,
            "default_response": "Not configured",
        });
        self.response_from_media_type(request, "geodns", data)
    }
    
    fn traffic_steering_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "Traffic Steering",
            // TODO: Implement traffic steering manager
            "enabled": false,
            "active_policies": 0,
            "traffic_splits": 0,
            "ab_tests": 0,
            "redirects": 0,
            "canary_deployments": 0,
        });
        self.response_from_media_type(request, "traffic_steering", data)
    }
    
    fn health_checks_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get basic server health indicators
        let tcp_queries = self.context.statistics.get_tcp_query_count();
        let udp_queries = self.context.statistics.get_udp_query_count();
        let server_responsive = tcp_queries > 0 || udp_queries > 0;
        
        let data = serde_json::json!({
            "title": "Health Checks",
            "server_status": if server_responsive { "Healthy" } else { "Starting" },
            "dns_port_status": if self.context.enable_udp || self.context.enable_tcp { "Listening" } else { "Disabled" },
            "api_port_status": if self.context.enable_api { "Listening" } else { "Disabled" },
            "zones_loaded": if let Ok(zones) = self.context.authority.read() { zones.zones().len() } else { 0 },
            // TODO: Implement endpoint health check manager
            "healthy_endpoints": 0,
            "degraded_endpoints": 0,
            "unhealthy_endpoints": 0,
            "uptime_percent": 100.0, // TODO: Calculate real uptime from start time
        });
        self.response_from_media_type(request, "health_checks", data)
    }
    
    fn logs_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get real statistics from context
        let tcp_count = self.context.statistics.get_tcp_query_count();
        let udp_count = self.context.statistics.get_udp_query_count();
        let total_logs = tcp_count + udp_count;
        
        let data = serde_json::json!({
            "title": "Query Logs",
            "total_queries": total_logs,
            "tcp_queries": tcp_count,
            "udp_queries": udp_count,
            "recent_queries": [], // TODO: Implement query log storage
            // TODO: Track errors and warnings in metrics
            "error_count": 0,
            "warning_count": 0,
            "log_level": "INFO",
            "log_size": "N/A", // TODO: Calculate actual log size
        });
        self.response_from_media_type(request, "logs", data)
    }
    
    fn alerts_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "Alerts",
            // TODO: Implement alert manager
            "active_alerts": 0,
            "critical_alerts": 0,
            "warning_alerts": 0,
            "info_alerts": 0,
            "alerts": [],
            "notification_channels": 0,
            "alert_rules": 0,
        });
        self.response_from_media_type(request, "alerts", data)
    }
    
    fn api_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get user count for API usage context
        let user_count = self.user_manager.list_users().unwrap_or_default().len();
        let session_count = self.user_manager.list_sessions(None).unwrap_or_default().len();
        
        let data = serde_json::json!({
            "title": "API & GraphQL",
            "api_enabled": self.context.enable_api,
            "graphql_enabled": true,
            "doh_enabled": self.doh_server.is_enabled(),
            "active_users": user_count,
            "active_sessions": session_count,
            // TODO: Implement API key management
            "api_keys": 0,
            // TODO: Track API request metrics
            "requests_today": 0,
            "avg_response_time": 0,
        });
        self.response_from_media_type(request, "api", data)
    }
    
    fn webhooks_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "Webhooks",
            // TODO: Implement webhook functionality
            "enabled": false,
            "active_webhooks": 0,
            "pending_deliveries": 0,
            "failed_deliveries": 0,
            "success_rate": 0.0,
            "supported_events": [],
        });
        self.response_from_media_type(request, "webhooks", data)
    }
    
    fn certificates_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get SSL configuration from context
        let ssl_enabled = self.context.ssl_config.enabled;
        let acme_enabled = self.context.ssl_config.acme.is_some();
        let acme_provider = if let Some(ref acme_config) = self.context.ssl_config.acme {
            match &acme_config.provider {
                crate::dns::acme::AcmeProvider::LetsEncrypt => "Let's Encrypt",
                crate::dns::acme::AcmeProvider::LetsEncryptStaging => "Let's Encrypt (Staging)",
                crate::dns::acme::AcmeProvider::ZeroSSL => "ZeroSSL",
                crate::dns::acme::AcmeProvider::Custom { url } => "Custom",
            }
        } else {
            "None"
        };
        
        let data = serde_json::json!({
            "title": "SSL/ACME Certificates",
            "ssl_enabled": ssl_enabled,
            "acme_enabled": acme_enabled,
            "acme_provider": acme_provider,
            "ssl_port": self.context.ssl_config.port,
            "cert_path": self.context.ssl_config.cert_path.as_ref().map(|p| p.to_string_lossy()).unwrap_or("Not configured".into()),
            "key_path": self.context.ssl_config.key_path.as_ref().map(|p| p.to_string_lossy()).unwrap_or("Not configured".into()),
            // TODO: Implement certificate status checking
            "certificate_valid": ssl_enabled,
            "days_until_expiry": 0,
            "auto_renewal_enabled": acme_enabled,
        });
        self.response_from_media_type(request, "certificates", data)
    }
    
    // Security API endpoints
    
    fn add_firewall_rule(&self, request: &mut Request) -> Result<ResponseBox> {
        // Parse firewall rule from request
        let rule: crate::dns::security::firewall::FirewallRule = if request.json_input() {
            serde_json::from_reader(request.as_reader())?            
        } else {
            return Err(WebError::InvalidInput("Firewall rules must be submitted as JSON".into()));
        };
        
        // Add rule to security manager
        self.context.security_manager.add_firewall_rule(rule)
            .map_err(|e| WebError::InternalError(format!("Failed to add firewall rule: {}", e)))?;
        
        Ok(Response::empty(201)
            .with_header(Self::safe_header("Content-Type: application/json"))
            .boxed())
    }
    
    fn delete_firewall_rule(&self, _request: &Request, rule_id: &str) -> Result<ResponseBox> {
        // Remove rule from security manager
        self.context.security_manager.remove_firewall_rule(rule_id)
            .map_err(|e| WebError::InternalError(format!("Failed to remove firewall rule: {}", e)))?;
        
        Ok(Response::empty(204).boxed())
    }
    
    fn load_blocklist(&self, request: &mut Request) -> Result<ResponseBox> {
        // Parse blocklist request
        let blocklist_req: serde_json::Value = if request.json_input() {
            serde_json::from_reader(request.as_reader())?
        } else {
            return Err(WebError::InvalidInput("Blocklist must be submitted as JSON".into()));
        };
        
        let source = blocklist_req["source"].as_str()
            .ok_or_else(|| WebError::InvalidInput("Missing 'source' field".into()))?;
        let category_str = blocklist_req["category"].as_str()
            .unwrap_or("Custom");
        
        // Map category string to enum
        let category = match category_str {
            "Malware" => crate::dns::security::firewall::ThreatCategory::Malware,
            "Phishing" => crate::dns::security::firewall::ThreatCategory::Phishing,
            "Botnet" => crate::dns::security::firewall::ThreatCategory::Botnet,
            _ => crate::dns::security::firewall::ThreatCategory::Custom,
        };
        
        // Load blocklist
        self.context.security_manager.load_blocklist(source, category)
            .map_err(|e| WebError::InternalError(format!("Failed to load blocklist: {}", e)))?;
        
        Ok(Response::empty(201).boxed())
    }
    
    fn load_allowlist(&self, request: &mut Request) -> Result<ResponseBox> {
        // Parse allowlist request
        let allowlist_req: serde_json::Value = if request.json_input() {
            serde_json::from_reader(request.as_reader())?
        } else {
            return Err(WebError::InvalidInput("Allowlist must be submitted as JSON".into()));
        };
        
        let source = allowlist_req["source"].as_str()
            .ok_or_else(|| WebError::InvalidInput("Missing 'source' field".into()))?;
        
        // Load allowlist
        self.context.security_manager.load_allowlist(source)
            .map_err(|e| WebError::InternalError(format!("Failed to load allowlist: {}", e)))?;
        
        Ok(Response::empty(201).boxed())
    }
    
    fn unblock_client(&self, _request: &Request, client_ip: &str) -> Result<ResponseBox> {
        // Parse IP address
        let ip_addr = client_ip.parse::<std::net::IpAddr>()
            .map_err(|_| WebError::InvalidInput("Invalid IP address".into()))?;
        
        // Unblock client
        self.context.security_manager.unblock_client(ip_addr);
        
        Ok(Response::empty(204).boxed())
    }
    
    fn get_security_metrics(&self, request: &Request) -> Result<ResponseBox> {
        let metrics = self.context.security_manager.get_metrics();
        let stats = self.context.security_manager.get_statistics();
        
        let data = serde_json::json!({
            "metrics": metrics,
            "statistics": stats,
        });
        
        if request.json_output() {
            let json_string = serde_json::to_string(&data)?;
            Ok(Response::from_string(json_string)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            self.response_from_media_type(request, "security_metrics", data)
        }
    }
    
    fn get_security_alerts(&self, request: &Request) -> Result<ResponseBox> {
        let limit = 100; // Default limit
        let alerts = self.context.security_manager.get_alerts(limit);
        
        let data = serde_json::json!({
            "alerts": alerts,
        });
        
        if request.json_output() {
            let json_string = serde_json::to_string(&data)?;
            Ok(Response::from_string(json_string)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            self.response_from_media_type(request, "security_alerts", data)
        }
    }
    
    fn get_security_events(&self, request: &Request) -> Result<ResponseBox> {
        let limit = 1000; // Default limit
        let events = self.context.security_manager.get_events(limit);
        
        let data = serde_json::json!({
            "events": events,
        });
        
        if request.json_output() {
            let json_string = serde_json::to_string(&data)?;
            Ok(Response::from_string(json_string)
                .with_header(Self::safe_header("Content-Type: application/json"))
                .boxed())
        } else {
            self.response_from_media_type(request, "security_events", data)
        }
    }
    
    fn settings_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get current server configuration
        let data = serde_json::json!({
            "title": "Settings",
            "dns_port": self.context.dns_port,
            "api_port": self.context.api_port,
            "ssl_port": self.context.ssl_config.port,
            "udp_enabled": self.context.enable_udp,
            "tcp_enabled": self.context.enable_tcp,
            "api_enabled": self.context.enable_api,
            "ssl_enabled": self.context.ssl_config.enabled,
            "recursive_enabled": self.context.allow_recursive,
            "zones_directory": &*self.context.zones_dir,
            "resolve_strategy": match self.context.resolve_strategy {
                crate::dns::context::ResolveStrategy::Recursive => "Recursive",
                crate::dns::context::ResolveStrategy::Forward { .. } => "Forward",
            },
        });
        self.response_from_media_type(request, "settings", data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Helper function to create a test server
    fn create_test_server() -> WebServer {
        // Create a minimal context for testing
        let context = Arc::new(crate::dns::context::ServerContext::new().expect("Failed to create test context"));
        WebServer::new(context)
    }
    
    #[test]
    fn test_calculate_response_string_size() {
        let server = create_test_server();
        
        // Test with 200 OK response
        let content = "Hello, World!";
        let size = server.calculate_response_string_size(content, 200);
        
        // Status line + headers + content
        assert!(size >= content.len() as u64, "Size should include content");
        assert!(size >= 150, "Size should include estimated headers");
    }
    
    #[test]
    fn test_calculate_response_string_size_error_responses() {
        let server = create_test_server();
        
        // Test 404 response
        let error_message = "Not Found";
        let size_404 = server.calculate_response_string_size(error_message, 404);
        assert!(size_404 >= error_message.len() as u64, "Size should include error message");
        assert!(size_404 >= 150, "Size should include headers for error response");
        
        // Test 500 response
        let error_message = "Internal Server Error";
        let size_500 = server.calculate_response_string_size(error_message, 500);
        assert!(size_500 >= error_message.len() as u64, "Size should include error message");
        assert!(size_500 >= 150, "Size should include headers for error response");
        
        // Test 401 response
        let error_message = "Unauthorized";
        let size_401 = server.calculate_response_string_size(error_message, 401);
        assert!(size_401 >= error_message.len() as u64, "Size should include error message");
        assert!(size_401 >= 150, "Size should include headers for error response");
    }
    
    #[test]
    fn test_error_status_code_mapping() {
        let server = create_test_server();
        
        // Test authentication error -> 401
        assert_eq!(server.error_status_code(&WebError::AuthenticationError("test".into())), 401);
        
        // Test authorization error -> 403
        assert_eq!(server.error_status_code(&WebError::AuthorizationError("test".into())), 403);
        
        // Test not found errors -> 404
        assert_eq!(server.error_status_code(&WebError::UserNotFound), 404);
        assert_eq!(server.error_status_code(&WebError::ZoneNotFound), 404);
        
        // Test generic error -> 500
        let generic_error = WebError::DatabaseError("test".into());
        assert_eq!(server.error_status_code(&generic_error), 500);
    }
    
    #[test]
    fn test_estimate_response_box_size() {
        let server = create_test_server();
        
        // Create a mock ResponseBox (we can't easily create a real one in tests)
        // Just test that the function returns a reasonable estimate
        let response = Response::from_string("test").boxed();
        let size = server.estimate_response_box_size(&response);
        
        // Should return a reasonable estimate
        assert!(size > 0, "Size estimate should be positive");
        assert!(size >= 220, "Size should include status line and headers estimate");
    }
}
