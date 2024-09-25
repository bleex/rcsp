use actix_web::{error, web, App, Error, HttpResponse, HttpServer};
use serde::Deserialize;
use futures::StreamExt;

#[actix_web::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let (send, recv) = crossbeam::channel::unbounded();
    let server = HttpServer::new(move || {
        let send = send.clone();
        App::new()
            .route("/", web::get().to(get_index))
            .route("/csp",
                web::post().to(move |body: web::Payload| post_csp(body, send.clone()))
                )
    });

    println!("Serving on http://localhost:5000...");
    server
        .bind("127.0.0.1:5000").expect("error binding server to address")
        .run()
        .await
        .expect("error running server");
}

async fn get_index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(
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
struct CspReport {
    csp_report: Csp,
}

const MAX_SIZE: usize = 262_144; // max payload size is 256k

async fn post_csp(
    mut info: web::Payload,
    send: crossbeam::channel::Sender<u32>,
) -> Result<HttpResponse, Error> {
    let response =
        format!("Nothing");
    let mut body = web::BytesMut::new();
    while let Some(chunk) = info.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }
    let msg = match serde_json::from_slice::<CspReport>(&body) {
        Ok(obj) => {
            format!("{:?}", obj);
        },
        Err(_e) => {
            format!("{:?}", body);
        },
    };
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(response))
}

