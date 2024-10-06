use actix_web::{error, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use crossbeam::channel::{unbounded, Receiver, Sender};
use futures::StreamExt;
use lapin::{options::*, BasicProperties, Channel, Connection, ConnectionProperties};
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
    let uri = "amqp://localhost:5672";
    let options = ConnectionProperties::default();
    let conn = Connection::connect(uri, options).await.unwrap();
    let channel = conn.create_channel().await.unwrap();
    let chclone = channel.clone();

    thread::spawn(|| process_logs(rxclone, chclone));
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
#[allow(dead_code)]
struct CspContainer {
    csp: Option<serde_json::Value>,
    invalid_csp: Option<String>,
    conn_info: Option<ConnInfo>,
}

impl Default for CspContainer {
    fn default() -> CspContainer {
        CspContainer {
            csp: None,
            invalid_csp: None,
            conn_info: None,
        }
    }
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
    let mut conn_info: ConnInfo = ConnInfo::default();
    if let Some(addr) = req.peer_addr() {
        conn_info.ipaddr = Some(addr.to_string());
    }
    for (hn, hv) in req.headers() {
        match hn.as_str() {
            "host" => conn_info.host = Some(format!("{:?}", hv)),
            "x-forwarded-for" => conn_info.x_forwarded_for = Some(format!("{:?}", hv)),
            "x-forwarded-host" => conn_info.x_forwarded_host = Some(format!("{:?}", hv)),
            "x-forwarded-proto" => conn_info.x_forwarded_proto = Some(format!("{:?}", hv)),
            "x-forwarded-port" => conn_info.x_forwarded_port = Some(format!("{:?}", hv)),
            "x-real-ip" => conn_info.x_real_ip = Some(format!("{:?}", hv)),
            _ => {}
        }
    }

    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(csp) => {
            let mut obj = CspContainer::default();
            obj.conn_info = Some(conn_info);
            obj.csp = Some(csp);
            tx.send(format!(r#"{:?}"#, obj)).unwrap()
        }
        Err(_e) => {
            let mut obj = CspContainer::default();
            obj.conn_info = Some(conn_info);
            obj.invalid_csp = Some(format!("{:?}", body));
            tx.send(format!(r#"{:?}"#, obj)).unwrap()
        }
    }
    Ok(HttpResponse::Ok().content_type("text/html").body(response))
}

fn process_logs(rx: Receiver<String>, cx: Channel) {
    while let Ok(msg) = rx.recv() {
        println!("{}", msg);
        async_global_executor::block_on(async {
            let _res = cx
                .basic_publish(
                    "",
                    "csp",
                    BasicPublishOptions::default(),
                    msg.as_bytes(),
                    BasicProperties::default(),
                )
                .await
                .unwrap()
                .await
                .unwrap();
        })
    }
}
