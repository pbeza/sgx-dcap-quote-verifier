use rocket::fs::TempFile;
use rocket::tokio::io::AsyncReadExt;
use sgx_dcap_quote_verifier::ecdsa_quote_verification;

#[macro_use]
extern crate rocket;

// https://api.rocket.rs/v0.5/rocket/fs/enum.TempFile.html#method.open

#[post("/verify", data = "<quote_file>")]
async fn sgx_quote_verify_from_file(quote_file: TempFile<'_>) -> std::io::Result<()> {
    let mut contents = Vec::new();
    quote_file.open().await?.read_to_end(&mut contents).await?;
    println!("success! hej!");
    ecdsa_quote_verification(&contents);
    Ok(())
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount(
        "/sgx",
        // routes![sgx_quote_verify, sgx_quote_verify_from_file],
        routes![sgx_quote_verify_from_file],
    )
}
