use actix_web::{error, web, App, Error, HttpResponse, HttpServer};
use crossbeam::channel::{unbounded, Receiver, Sender};
use futures::StreamExt;
use serde::Deserialize;
use std::thread;

#[actix_web::main]
async fn main() {
    env_logger::init();
    let (tx, rx) = unbounded();
    let txclone: Sender<String> = tx.clone();
    let rxclone: Receiver<String> = rx.clone();
    let server = HttpServer::new(move || {
        let tx = tx.clone();
        App::new().route("/", web::get().to(get_index)).route(
            "/csp",
            web::post().to(move |body: web::Payload| post_csp(body, tx.clone())),
        )
    });
    thread::spawn(|| process_logs(txclone, rxclone));
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
    blocked_uri: String,
    column_number: u32,
    disposition: String,
    document_uri: String,
    effective_directive: String,
    original_policy: String,
    referrer: String,
    status_code: u32,
    violated_directive: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
struct CspReport {
    csp_report: Csp,
}

const MAX_SIZE: usize = 262_144; // max payload size is 256k

async fn post_csp(mut info: web::Payload, tx: Sender<String>) -> Result<HttpResponse, Error> {
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
    match serde_json::from_slice::<CspReport>(&body) {
        Ok(obj) => {
            tx.send(format!("{:?}", obj)).unwrap();
        }
        Err(_e) => {
            tx.send(format!("{:?}", body)).unwrap();
        }
    };
    Ok(HttpResponse::Ok().content_type("text/html").body(response))
}

fn process_logs(_tx: Sender<String>, rx: Receiver<String>) {
    loop {
        match rx.recv() {
            Ok(msg) => {
                println!("{}", msg);
            }
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }
}
