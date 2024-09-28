use actix_web::{error, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use crossbeam::channel::{unbounded, Receiver, Sender};
use futures::StreamExt;
use serde::Deserialize;
use std::thread;

#[actix_web::main]
async fn main() {
    env_logger::init();
    let (tx, rx) = unbounded();
    let rxclone: Receiver<String> = rx.clone();
    let server = HttpServer::new(move || {
        let tx = tx.clone();
        App::new().route("/", web::get().to(get_index)).route(
            "/csp",
            web::post()
                .to(move |req: HttpRequest, body: web::Payload| post_csp(req, body, tx.clone())),
        )
    });
    thread::spawn(|| process_logs(rxclone));
    println!("Serving on http://localhost:5000...");
    server
        .bind("127.0.0.1:5000")
        .expect("error binding server to address")
        .run()
        .await
        .expect("error running server");
}

async fn get_index() -> HttpResponse {
    HttpResponse::Ok().content_type("text/html").body(
        r#"
                <title>CSP Reporting server</title>
                <form action="/csp" method="post">
                <input type="text" name="csp"/>
                <button type="submit">Post CSP report manually</button>
                </form>
            "#,
    )
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
struct Csp {
    blocked_uri: Option<String>,
    column_number: Option<u32>,
    disposition: Option<String>,
    document_uri: Option<String>,
    effective_directive: Option<String>,
    line_number: Option<u32>,
    original_policy: Option<String>,
    referrer: Option<String>,
    script_sample: Option<String>,
    source_file: Option<String>,
    status_code: Option<u32>,
    violated_directive: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
struct CspReport {
    csp_report: Option<Csp>,
    invalid_csp: Option<String>,
    conn_details: Option<ConnInfo>,
}

impl Default for CspReport {
    fn default() -> CspReport {
        CspReport {
            csp_report: None,
            invalid_csp: None,
            conn_details: None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
struct ConnInfo {
    host: Option<String>,
    ipaddr: Option<String>,
    x_forwarded_for: Option<String>,
    x_forwarded_host: Option<String>,
    x_forwarded_proto: Option<String>,
    x_forwarded_port: Option<String>,
    x_real_ip: Option<String>,
}

impl Default for ConnInfo {
    fn default() -> ConnInfo {
        ConnInfo {
            host: None,
            ipaddr: None,
            x_forwarded_for: None,
            x_forwarded_host: None,
            x_forwarded_proto: None,
            x_forwarded_port: None,
            x_real_ip: None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code, non_snake_case)]
struct CspContent {
    blockedURL: String,
    columnNumber: u32,
    disposition: String,
    documentURL: String,
    effectiveDirective: String,
    lineNumber: u32,
    originalPolicy: String,
    referrer: String,
    sample: String,
    sourceFile: String,
    statusCode: u32,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct CspReporting {
    age: u32,
    body: CspContent,
    r#type: String,
    url: String,
    user_agent: String,
}

const MAX_SIZE: usize = 262_144; // max payload size is 256k

async fn post_csp(
    req: HttpRequest,
    mut info: web::Payload,
    tx: Sender<String>,
) -> Result<HttpResponse, Error> {
    let response = format!("Nothing");
    let mut body = web::BytesMut::new();
    while let Some(chunk) = info.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }
    let mut conn_details: ConnInfo = ConnInfo::default();
    if let Some(addr) = req.peer_addr() {
        conn_details.ipaddr = Some(addr.to_string());
    }
    for (hn, hv) in req.headers() {
        match hn.as_str() {
            "host" => conn_details.host = Some(format!("{:?}", hv)),
            "x-forwarded-for" => conn_details.x_forwarded_for = Some(format!("{:?}", hv)),
            "x-forwarded-host" => conn_details.x_forwarded_host = Some(format!("{:?}", hv)),
            "x-forwarded-proto" => conn_details.x_forwarded_proto = Some(format!("{:?}", hv)),
            "x-forwarded-port" => conn_details.x_forwarded_port = Some(format!("{:?}", hv)),
            "x-real-ip" => conn_details.x_real_ip = Some(format!("{:?}", hv)),
            _ => {}
        }
    }

    match serde_json::from_slice::<CspReport>(&body) {
        Ok(mut obj) => {
            obj.conn_details = Some(conn_details);
            tx.send(format!(r#"{:?}"#, obj)).unwrap()
        }
        Err(_e) => {
            let mut obj = CspReport::default();
            obj.conn_details = Some(conn_details);
            obj.invalid_csp = Some(format!("{:?}", body));
            tx.send(format!(r#"{:?}"#, obj)).unwrap()
        }
    };
    Ok(HttpResponse::Ok().content_type("text/html").body(response))
}

fn process_logs(rx: Receiver<String>) {
    while let Ok(msg) = rx.recv() {
        println!("{}", msg);
    }
}
