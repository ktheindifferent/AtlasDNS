use std::sync::Arc;

use std::path::{Path};

use std::thread;


use handlebars::Handlebars;
use tiny_http::{Method, Request, Response, ResponseBox, Server};

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use crate::dns::context::ServerContext;
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
                .register_template_string(name, data.to_string()).is_err()
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

    pub fn run_webserver(self, use_ssl: bool) {

        let webserver = match Server::http(("0.0.0.0", self.context.api_port)) {
            Ok(x) => x,
            Err(e) => {
                log::info!("Failed to start web server: {:?}", e);
                return;
            }
        };

        log::info!(
            "Web server started and listening on {}",
            self.context.api_port
        );

        for mut request in webserver.incoming_requests() {
            log::info!("HTTP {:?} {:?}", request.method(), request.url());

            let url = request.url().to_string();
            let method = request.method();

            let url_parts: Vec<&str> = url.split("/").filter(|x| *x != "").collect();
            let response = match (method, url_parts.as_slice()) {
                (Method::Post, ["authority", zone]) => self.record_create(&mut request, zone),
                (Method::Delete, ["authority", zone]) => self.record_delete(&mut request, zone),
                (Method::Post, ["authority", zone, "delete_record"]) => self.record_delete(&mut request, zone),
                (Method::Get, ["authority", zone]) => self.zone_view(&request, zone),
                (Method::Post, ["authority"]) => self.zone_create(&mut request),
                (Method::Get, ["authority"]) => self.zone_list(&request),
                (Method::Get, ["cache"]) => self.cacheinfo(&request),
                (Method::Get, []) => self.index(&request),
                (_, _) => self.not_found(&request),
            };

            let response_result = match response {
                Ok(response) => request.respond(response),
                Err(err) if request.json_output() => {
                    log::info!("Request failed: {:?}", err);
                    let error = serde_json::to_string(&serde_json::json!({
                        "message": err.to_string(),
                    }))
                    .unwrap();
                    request.respond(Response::from_string(error))
                }
                Err(err) => {
                    log::info!("Request failed: {:?}", err);
                    request.respond(Response::from_string(err.to_string()))
                }
            };

            if let Err(err) = response_result {
                log::info!("Failed to write response to client: {:?}", err);
            }
        }

    }

    fn handle_requests(self, requests: tiny_http::IncomingRequests){
        for mut request in requests {
            log::info!("HTTP {:?} {:?}", request.method(), request.url());

            let mut content = String::new();
            request.as_reader().read_to_string(&mut content).unwrap();
            log::info!("key: {}", content);

            let url = request.url().to_string();
            let method = request.method();

            // let mut sessions :Vec<ckitl::Session> = Vec::new();
            // if Path::new("/opt/atlas/dat/sessions.bin").exists() {
			// 	sessions = ckitl::load_sessions(Arc::clone(&self.ckitl_server)).unwrap().sessions;
			// }

            let mut session_authenticated = true;
            let mut session_key = "";
			// for session in &sessions{
			// 	if content.contains(&session.id) || request.url().contains(&session.id) {
			// 		session_authenticated = true;
            //         session_key = session.id.as_str();
			// 	} 
			// }


            if session_authenticated{

                let formated_key = format!("?key={}", session_key).as_str();

                let formated_authority_key = format!("authority?key={}", session_key).as_str();
                let formated_cache_key = format!("cache?key={}", session_key).as_str();

                let url_parts: Vec<&str> = url.split('/').filter(|x| x != &"").collect();
                let response = match (method, url_parts.as_slice()) {
                    (Method::Post, ["authority", zone, formated_key]) => self.record_create(&mut request, zone),
                    (Method::Delete, ["authority", zone, formated_key]) => self.record_delete(&mut request, zone),
                    (Method::Post, ["authority", zone, "delete_record", formated_key]) => self.record_delete(&mut request, zone),
                    (Method::Get, ["authority", zone, formated_key]) => self.zone_view(&request, zone),
                    (Method::Post, [formated_authority_key]) => self.zone_create(&mut request),
                    (Method::Get, [formated_authority_key]) => self.zone_list(&request),
                    (Method::Get, [formated_cache_key]) => self.cacheinfo(&request),
                    (Method::Get, [formated_key]) => self.index(&request),
                    (_, _) => self.not_found(&request),
                };
                let header = tiny_http::Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
                let response_result = match response {
                    Ok(response) => request.respond(response.with_header(header)),
                    Err(err) if request.json_output() => {
                        log::info!("Request failed: {:?}", err);
                        let error = serde_json::to_string(&serde_json::json!({
                            "message": err.to_string(),
                        }))
                        .unwrap();
                        request.respond(Response::from_string(error).with_header(header))
                    }
                    Err(err) => {
                        log::info!("Request failed: {:?}", err);
                        request.respond(Response::from_string(err.to_string()).with_header(header))
                    }
                };
    
                if let Err(err) = response_result {
                    log::info!("Failed to write response to client: {:?}", err);
                }
            }


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
