use std::sync::Arc;
use std::fs;



use handlebars::Handlebars;
use tiny_http::{Method, Request, Response, ResponseBox, Server, SslConfig as TinyHttpSslConfig};


use crate::dns::context::ServerContext;
use crate::dns::acme::AcmeCertificateManager;
use crate::web::{
    authority, cache, index,
    util::{parse_formdata, FormDataDecodable},
    Result,
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
}

impl<'a> WebServer<'a> {
    pub fn new(context: Arc<ServerContext>) -> WebServer<'a> {
        let mut server = WebServer {
            context,
            handlebars: Handlebars::new(),
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
}
