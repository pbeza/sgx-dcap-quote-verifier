use rocket::data::ByteUnit;
// use rocket::form::Form;
use rocket::tokio::io::AsyncReadExt;
use rocket::Data;
use sgx_dcap_quote_verifier::ecdsa_quote_verification;

#[macro_use]
extern crate rocket;

// #[post("/", data = "<quote>")]
// fn sgx_quote_verify(quote: Form<&str>) -> String {
//     ecdsa_quote_verification(quote.as_bytes());
//     format!("Hello, world! {}", *quote)
// }

#[post("/", data = "<quote>")]
async fn sgx_quote_verify_from_file<'a>(quote: Data<'_>) -> String {
    let mut buffer = Vec::new();
    quote
        .open(ByteUnit::default())
        .read_to_end(&mut buffer)
        .await
        .unwrap();
    ecdsa_quote_verification(&buffer);
    format!("Hello, world! {}", String::from_utf8_lossy(&buffer))
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount(
        "/sgx",
        // routes![sgx_quote_verify, sgx_quote_verify_from_file],
        routes![sgx_quote_verify_from_file],
    )
}
