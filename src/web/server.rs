use std::sync::Arc;
use std::fs;



use handlebars::Handlebars;
use tiny_http::{Method, Request, Response, ResponseBox, Server, SslConfig as TinyHttpSslConfig};


use crate::dns::context::ServerContext;
use crate::dns::acme::AcmeCertificateManager;
use crate::web::{
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
}

impl<'a> WebServer<'a> {
    pub fn new(context: Arc<ServerContext>) -> WebServer<'a> {
        let user_manager = Arc::new(UserManager::new());
        let session_middleware = Arc::new(SessionMiddleware::new(user_manager.clone()));
        
        let mut handlebars = Handlebars::new();
        
        // Register the 'eq' helper for comparing values in templates
        handlebars.register_helper(
            "eq",
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let param1 = h.param(0).and_then(|v| v.value().as_str());
                let param2 = h.param(1).and_then(|v| v.value().as_str());
                
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
        
        let mut server = WebServer {
            context,
            handlebars,
            user_manager,
            session_middleware,
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
            (Method::Get, []) => self.index(request),
            (_, _) => self.not_found(request),
        }
    }

    /// Handle a single HTTP request
    fn handle_request(&self, mut request: tiny_http::Request) {
        log::info!("HTTP {:?} {:?}", request.method(), request.url());

        let response = self.route_request(&mut request);
        let response_result = self.send_response(request, response);

        if let Err(err) = response_result {
            log::info!("Failed to write response to client: {:?}", err);
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

    fn index(&self, request: &Request) -> Result<ResponseBox> {
        let index_result = index::index(&self.context)?;
        self.response_from_media_type(request, "index", index_result)
    }

    fn zone_list(&self, request: &Request) -> Result<ResponseBox> {
        let zone_list_result = authority::zone_list(&self.context)?;
        self.response_from_media_type(request, "authority", zone_list_result)
    }

    fn zone_view(&self, request: &Request, zone: &str) -> Result<ResponseBox> {
        let zone_view_result = authority::zone_view(&self.context, zone)?;
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
        self.response_from_media_type(request, "cache", cacheinfo_result)
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
        
        let user = self.user_manager
            .authenticate(&login_request.username, &login_request.password)
            .map_err(|e| WebError::AuthenticationError(e))?;
        
        let ip_address = self.session_middleware.get_ip_address(request);
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
            .map_err(|e| WebError::InvalidRequest)?;
        
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
}
