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
            .find(|x| x.field.as_str() == "Content-Type")
            .map(|x| {
                let value: String = x.value.clone().into();
                value.contains("application/json")
            })
            .unwrap_or_default()
    }

    fn json_output(&self) -> bool {
        self.headers()
            .iter()
            .find(|x| x.field.as_str() == "Accept")
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
            (Method::Post, ["dns-query"])
        );

        // Check authentication for protected routes
        if !is_public_route {
            // Check if user has a valid session
            if let Err(_) = self.session_middleware.validate_request(request) {
                // For API requests, return 401
                if request.json_output() {
                    return Ok(Response::from_string("{\"error\": \"Unauthorized\"}")
                        .with_status_code(401)
                        .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
                        .boxed());
                }
                // For web requests, redirect to login
                return Ok(Response::empty(302)
                    .with_header::<tiny_http::Header>("Location: /auth/login".parse().unwrap())
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
            
            // New UI routes
            (Method::Get, ["analytics"]) => self.analytics_page(request),
            (Method::Get, ["dnssec"]) => self.dnssec_page(request),
            (Method::Get, ["firewall"]) => self.firewall_page(request),
            (Method::Get, ["templates"]) => self.templates_page(request),
            (Method::Get, ["rate-limiting"]) => self.rate_limiting_page(request),
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
        let user_agent = request.headers()
            .iter()
            .find(|h| h.field.as_str() == "User-Agent")
            .map(|h| h.value.as_str())
            .unwrap_or("Unknown")
            .to_string(); // Convert to owned string
        
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
        
        // Log the HTTP request
        let request_log = HttpRequestLog {
            method: method.clone(),
            path: path.clone(),
            status_code,
            request_size: None, // TODO: Calculate request size
            response_size: None, // TODO: Calculate response size
            user_agent: Some(user_agent.clone()),
            referer: None, // TODO: Extract referer header
        };
        self.context.logger.log_http_request(&ctx, request_log);
        
        // Record metrics
        self.context.metrics.record_web_request(&method, &path, &status_code.to_string());
        self.context.metrics.record_web_duration(&method, &path, ctx.elapsed());

        let response_result = self.send_response(request, response);

        if let Err(err) = response_result {
            log::error!("Failed to write response to client: {:?}", err);
            self.context.metrics.record_error("web_server", "response_write_failed");
        }
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
                let error_string = serde_json::to_string(&error_json).unwrap();
                request.respond(Response::from_string(error_string))
            }
            Err(err) => {
                log::info!("Request failed: {:?}", err);
                request.respond(Response::from_string(err.to_string()))
            }
        }
    }

    pub fn run_webserver(self, use_ssl: bool) {
        if use_ssl && self.context.ssl_config.enabled {
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
                                .with_header(tiny_http::Header::from_bytes(&b"Location"[..], redirect_url.as_bytes()).unwrap());
                            
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
        Ok(if request.json_output() {
            Response::from_string(serde_json::to_string(&data)?)
                .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
                .boxed()
        } else {
            Response::from_string(self.handlebars.render(template, &data)?)
                .with_header::<tiny_http::Header>("Content-Type: text/html".parse().unwrap())
                .boxed()
        })
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

        let location_header = format!("Location: /authority/{}", zone.domain);

        Ok(
            Response::empty(if request.json_output() { 201 } else { 302 })
                .with_header::<tiny_http::Header>(location_header.parse().unwrap())
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

        let location_header = format!("Location: /authority/{}", zone);
        Ok(
            Response::empty(if request.json_output() { 201 } else { 302 })
                .with_header::<tiny_http::Header>(location_header.parse().unwrap())
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

        let location_header = format!("Location: /authority/{}", zone);
        Ok(
            Response::empty(if request.json_output() { 201 } else { 302 })
                .with_header::<tiny_http::Header>(location_header.parse().unwrap())
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
            .with_header::<tiny_http::Header>("Content-Type: text/plain; version=0.0.4; charset=utf-8".parse().unwrap())
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
            serde_json::from_reader(request.as_reader())?
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
                .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
                .boxed())
        } else {
            Ok(Response::empty(302)
                .with_header(create_session_cookie(&session.token))
                .with_header::<tiny_http::Header>("Location: /".parse().unwrap())
                .boxed())
        }
    }
    
    fn logout(&self, request: &mut Request) -> Result<ResponseBox> {
        if let Some(token) = self.session_middleware.extract_token(request) {
            let _ = self.user_manager.invalidate_session(&token);
        }
        
        if request.json_output() {
            Ok(Response::from_string("{\"success\":true}")
                .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
                .boxed())
        } else {
            Ok(Response::empty(302)
                .with_header(clear_session_cookie())
                .with_header::<tiny_http::Header>("Location: /auth/login".parse().unwrap())
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
                .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
                .boxed())
        } else {
            Ok(Response::empty(302)
                .with_header::<tiny_http::Header>("Location: /users".parse().unwrap())
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
                .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
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
            .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
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
            .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
            .boxed())
    }
    
    fn graphql_playground(&self, _request: &Request) -> Result<ResponseBox> {
        Ok(Response::from_string(graphql_playground())
            .with_header::<tiny_http::Header>("Content-Type: text/html; charset=utf-8".parse().unwrap())
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
            .with_header::<tiny_http::Header>("Content-Type: application/json".parse().unwrap())
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
        
        let data = serde_json::json!({
            "title": "Analytics",
            "total_queries": total_queries,
            "tcp_queries": tcp_count,
            "udp_queries": udp_count,
            "cache_entries": cache_size,
            "tcp_percent": tcp_percent,
            "udp_percent": udp_percent,
            // TODO: Add cache hit rate tracking to metrics
            "cache_hit_rate": 0,
            // TODO: Add response time tracking to metrics
            "avg_response_time": 0.0,
            // TODO: Add unique client tracking
            "unique_clients": 0,
            // TODO: Add response code tracking to metrics
            "noerror_count": 0,
            "noerror_percent": 0,
            "nxdomain_count": 0,
            "nxdomain_percent": 0,
            "servfail_count": 0,
            "servfail_percent": 0,
            "other_count": 0,
            "other_percent": 0,
            // TODO: Add query type tracking to metrics
            "a_count": 0,
            "a_percent": 0,
            "aaaa_count": 0,
            "aaaa_percent": 0,
            "cname_count": 0,
            "cname_percent": 0,
            "mx_count": 0,
            "mx_percent": 0,
            "txt_count": 0,
            "txt_percent": 0,
            // TODO: Add latency percentile tracking to metrics
            "p50_latency": 0,
            "p90_latency": 0,
            "p95_latency": 0,
            "p99_latency": 0,
            // TODO: Add DoH/DoT/DoQ protocol tracking
            "doh_percent": 0,
            "dot_percent": 0,
            "doq_percent": 0,
        });
        self.response_from_media_type(request, "analytics", data)
    }
    
    fn dnssec_page(&self, request: &Request) -> Result<ResponseBox> {
        // Get real zone count from authority
        let total_zones = if let Ok(zones) = self.context.authority.read() {
            zones.zones().len()
        } else {
            0
        };
        
        let data = serde_json::json!({
            "title": "DNSSEC Management",
            "total_zones": total_zones,
            // TODO: Implement DNSSEC support
            "signed_zones": 0,
            "signed_percent": 0,
            "active_keys": 0,
            "ksk_count": 0,
            "zsk_count": 0,
            "pending_rollovers": 0,
            "next_rollover_days": 0,
            "last_check": "Not implemented",
        });
        self.response_from_media_type(request, "dnssec", data)
    }
    
    fn firewall_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "DNS Firewall",
            // TODO: Implement DNS firewall functionality
            "blocked_queries": 0,
            "active_rules": 0,
            "custom_rules": 0,
            "threat_feeds": 0,
            "block_rate": 0.0,
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
        let data = serde_json::json!({
            "title": "Rate Limiting",
            // TODO: Connect to rate limiting manager when implemented
            "throttled_queries": 0,
            "blocked_clients": 0,
            "active_limits": 0,
            "avg_qps": 0,
        });
        self.response_from_media_type(request, "rate_limiting", data)
    }
    
    fn ddos_protection_page(&self, request: &Request) -> Result<ResponseBox> {
        let data = serde_json::json!({
            "title": "DDoS Protection",
            // TODO: Implement DDoS protection functionality
            "blocked_attacks": 0,
            "detection_rules": 0,
            "threat_level": "Low",
            "auto_block_enabled": false,
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
            "zones_directory": self.context.zones_dir,
            "resolve_strategy": match self.context.resolve_strategy {
                crate::dns::context::ResolveStrategy::Recursive => "Recursive",
                crate::dns::context::ResolveStrategy::Forward { .. } => "Forward",
            },
        });
        self.response_from_media_type(request, "settings", data)
    }
}
