use std::net::Ipv4Addr;

use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, App, HttpServer};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, web};

#[actix_web::get("/login/{user}")]
async fn login(req: HttpRequest, user: web::Path<String>) -> impl Responder {
    let user = user.into_inner();
    println!("Login {user}");
    let body = format!("<h1>logged in {user}</h1>");
    Identity::login(&req.extensions(), user).unwrap();
    HttpResponse::Ok().body(body)
}

#[actix_web::get("/logout")]
async fn logout(id: Identity) -> impl Responder {
    println!("Logout");
    let user = id.id().unwrap();
    id.logout();
    let body = format!("<h1>logged out {user}</h1>");
    HttpResponse::Ok().body(body)
}
#[actix_web::get("/")]
async fn index(id: Option<Identity>) -> impl Responder {
    let msg = if let Some(id) = id {
        format!("logged in: {:?}", id.id())
    } else {
        String::from("not logged in")
    };
    println!("{}", msg);
    let body = format!("<h1>{msg}</h1>");
    HttpResponse::Ok().body(body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = Key::generate();

    let mut server = HttpServer::new(move || {
        App::new()
            .service(index)
            .service(login)
            .service(logout)
            // .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                key.clone(),
            ))
            .wrap(IdentityMiddleware::default())
    });
    let mut listenfd = listenfd::ListenFd::from_env();
    server = match listenfd.take_tcp_listener(0)? {
        Some(listener) => server.listen(listener)?,
        None => server.bind((Ipv4Addr::LOCALHOST, 8010))?,
    };

    server.run().await?;

    Ok(())
}
