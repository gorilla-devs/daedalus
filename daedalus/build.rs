fn main() {
    dotenvy::dotenv().ok();

    // read BRAND_NAME and SUPPORT_EMAIL and injects into the library
    let brand_name = dotenvy::var("BRAND_NAME").unwrap();
    let support_email = dotenvy::var("SUPPORT_EMAIL").unwrap();

    println!("cargo:rustc-env=BRAND_NAME={}", brand_name);
    println!("cargo:rustc-env=SUPPORT_EMAIL={}", support_email);
}
