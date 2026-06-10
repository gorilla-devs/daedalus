use backon::{ExponentialBuilder, Retryable};
use daedalus::Branding;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::ffi::OsStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tracing::{Instrument, error, info, instrument, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Shared mutex guarding the live-root PUT so the publish loop and the control
/// executor (§2.4) never write `v{CAS_VERSION}/manifest.json` concurrently.
/// The control executor acquires this before its rollback PUT; the publish loop
/// acquires it just before the live-root PUT below.
pub static ROOT_WRITE_LOCK: LazyLock<Arc<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

/// Stale-pin reminder threshold — warn in Discord once per cycle for any pin
/// older than this.
const PIN_STALE_THRESHOLD_HOURS: i64 = 6;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

/// Configuration constants
/// Update interval for fetching new metadata (1 hour)
const UPDATE_INTERVAL_SECS: u64 = 60 * 60;
/// Maximum number of concurrent upload operations
const MAX_CONCURRENT_UPLOADS: usize = 10;
/// Circuit breaker: number of consecutive failures before opening
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
/// Circuit breaker: duration to wait before retrying (5 minutes)
const CIRCUIT_BREAKER_RESET_TIMEOUT_SECS: u64 = 300;
/// Maximum number of retry attempts for uploads.
/// Combined with the should_retry classifier, transient S3 errors get a few
/// fast retries; permanent errors (auth/4xx) error out immediately.
const MAX_UPLOAD_RETRIES: usize = 5;
/// Maximum delay between retries (1 minute). Previous 30-minute cap meant a
/// doomed upload could block for hours.
const MAX_RETRY_DELAY_SECS: u64 = 60;

/// How often to poll the control file for pending operator actions.
/// Default 30 s; override via `CONTROL_POLL_INTERVAL_SECS` env var.
const DEFAULT_CONTROL_POLL_INTERVAL_SECS: u64 = 30;

mod common;
mod fabric;
mod forge;
mod infrastructure;
mod loaders;
mod minecraft;
mod neoforge;
mod quilt;
mod services;

/// Create a future that completes when a shutdown signal is received (SIGTERM or Ctrl+C)
async fn shutdown_signal() {
    // Both branches log+fall-through to `pending::<()>` if signal handler
    // installation fails — a panic here would kill the main loop, which is
    // the exact opposite of the "never crash" contract this service has.
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                warn!(error = %e, "Failed to install Ctrl+C handler; ignoring");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "Failed to install SIGTERM handler; ignoring");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        }
        _ = terminate => {
            info!("Received SIGTERM signal");
        }
    }
}

fn main() -> Result<(), crate::infrastructure::error::Error> {
    // Sentry init is optional even with the feature compiled in — missing
    // DSN logs a warning and skips, rather than panicking the process
    // before logging is even initialized.
    #[cfg(feature = "sentry")]
    let _guard = match dotenvy::var("SENTRY_DSN") {
        Ok(dsn) if !dsn.is_empty() => Some(sentry::init((
            dsn,
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        ))),
        _ => {
            eprintln!("SENTRY_DSN not set; Sentry reporting disabled");
            None
        }
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let use_json = dotenvy::var("LOG_FORMAT")
                .map(|v| v == "json")
                .unwrap_or(false);

            let filter = if std::env::var("RUST_LOG").is_ok() {
                println!("Loaded logger directives from RUST_LOG env");
                EnvFilter::from_env("RUST_LOG")
            } else {
                EnvFilter::new("daedalus_client=info")
            };

            // Initialize Discord notifier before subscriber init so the
            // tracing layer can forward error events from this point on.
            // try_init_from_env() is a no-op if DISCORD_WEBHOOK_URL is unset.
            let discord_handle = services::discord::try_init_from_env();
            let discord_layer = services::discord::DiscordTracingLayer::new();

            let betterstack_token = dotenvy::var("BETTERSTACK_TOKEN").ok();
            let betterstack_handle = if let Some(ref token) = betterstack_token {
                let betterstack_url = dotenvy::var("BETTERSTACK_URL")
                    .unwrap_or_else(|_| "https://in.logs.betterstack.com".to_string());

                let (betterstack_layer, handle) = services::betterstack::BetterstackLayer::new(
                    token.clone(),
                    betterstack_url,
                    None,
                    None,
                );

                if use_json {
                    let json_layer = tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_file(true)
                        .with_line_number(true);

                    tracing_subscriber::registry()
                        .with(json_layer)
                        .with(betterstack_layer)
                        .with(discord_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "json",
                        betterstack_enabled = true,
                        "Initialized JSON logging with Betterstack integration"
                    );
                } else {
                    let pretty_layer = tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(true)
                        .pretty()
                        .with_thread_names(true);

                    tracing_subscriber::registry()
                        .with(pretty_layer)
                        .with(betterstack_layer)
                        .with(discord_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "pretty",
                        betterstack_enabled = true,
                        "Initialized pretty logging with Betterstack integration"
                    );
                }

                Some(handle)
            } else {
                if use_json {
                    let json_layer = tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true)
                        .with_file(true)
                        .with_line_number(true);

                    tracing_subscriber::registry()
                        .with(json_layer)
                        .with(discord_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "json",
                        "Initialized JSON logging (production mode)"
                    );
                } else {
                    let pretty_layer = tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_ansi(true)
                        .pretty()
                        .with_thread_names(true);

                    tracing_subscriber::registry()
                        .with(pretty_layer)
                        .with(discord_layer)
                        .with(filter)
                        .init();

                    info!(
                        version = env!("CARGO_PKG_VERSION"),
                        format = "pretty",
                        "Initialized pretty logging (development mode)"
                    );
                }

                None
            };

            if check_env_vars() {
                return Err(crate::infrastructure::error::invalid_input("Some environment variables are missing!"));
            }

            // Propagate env / set_branding errors as Result so any future refactor
            // moving this into a hot path can't accidentally panic the loop.
            let brand_name = dotenvy::var("BRAND_NAME")
                .map_err(|_| crate::infrastructure::error::ErrorKind::EnvVarMissing("BRAND_NAME".into()))?;
            let support_email = dotenvy::var("SUPPORT_EMAIL")
                .map_err(|_| crate::infrastructure::error::ErrorKind::EnvVarMissing("SUPPORT_EMAIL".into()))?;
            Branding::set_branding(Branding::new(brand_name, support_email))
                .map_err(|e| crate::infrastructure::error::invalid_input(format!("Branding init failed: {e}")))?;

            // Env-tunable control-poll interval; default 30 s.
            let control_poll_interval_secs: u64 = dotenvy::var("CONTROL_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_CONTROL_POLL_INTERVAL_SECS);

            let mut publish_timer = tokio::time::interval(Duration::from_secs(UPDATE_INTERVAL_SECS));
            let mut control_timer = tokio::time::interval(Duration::from_secs(control_poll_interval_secs));
            // MissedTickBehavior::Delay: if a control tick is missed (e.g. because
            // a publish cycle was running), just schedule the next tick relative to
            // now rather than firing immediately N times to catch up.
            control_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS));

            {
                let uploaded_files = Arc::new(Mutex::new(Vec::new()));

                match upload_static_files(uploaded_files.clone(), semaphore.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        error!("{:?}", err);
                    }
                }
            }

            let mut is_first_run = true;

            loop {
                info!("Waiting for next publish timer, control poll, or shutdown signal");

                tokio::select! {
                    _ = publish_timer.tick() => {
                        let loop_span = tracing::info_span!("processing_cycle", is_first_run);
                        run_publish_cycle(is_first_run, semaphore.clone())
                            .instrument(loop_span)
                            .await;
                        is_first_run = false;
                    }
                    _ = control_timer.tick() => {
                        // §2.3: poll control.json for pending operator intents.
                        services::control::process_pending(&CLIENT).await;
                    }
                    _ = shutdown_signal() => {
                        info!("Shutdown signal received - exiting gracefully");
                        break;
                    }
                }
            }

            // Drain Betterstack + Discord buffers and ship one final batch
            // before process exit.
            if let Some(handle) = betterstack_handle {
                handle.shutdown().await;
            }
            if let Some(handle) = discord_handle {
                handle.shutdown().await;
            }

            info!("Application shutdown complete");
            Ok(())
        })
}

/// Execute one full publish cycle (all loaders).
///
/// Extracted from the select! branch so the publish branch stays short and
/// readable.  `is_first_run` controls whether first-cycle-specific behaviour
/// fires (currently passed through to `minecraft::retrieve_data`).
async fn run_publish_cycle(is_first_run: bool, semaphore: Arc<Semaphore>) {
    let uploader = services::upload::BatchUploader::new();
    let manifest_builder = services::cas::ManifestBuilder::new();

    // §1.4: run-state spans the whole cycle. Loaded up front so retrieval-phase
    // outcomes (a loader that is circuit-open or fails before we ever reach the
    // publish loop) get recorded, and saved once at the end regardless of which
    // path the cycle takes.
    let mut run_state = services::run_state::load(&CLIENT).await;

    let versions = {
        let span = tracing::info_span!("minecraft_processing");
        async {
            match MINECRAFT_BREAKER.call(async {
                minecraft::retrieve_data(
                    &uploader,
                    &manifest_builder,
                    &CLIENT,
                    semaphore.clone(),
                    is_first_run,
                )
                .await
            })
            .await
            {
                Ok(res) => {
                    info!(version_count = res.versions.len(), "Minecraft data retrieved");
                    Some(res)
                }
                Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                    warn!("Minecraft circuit breaker is open, skipping");
                    run_state
                        .loader_mut("minecraft")
                        .record_failure(services::run_state::LoaderOutcome::CircuitOpen);
                    None
                }
                Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                    error!(error = %err, "Minecraft processing failed");
                    run_state
                        .loader_mut("minecraft")
                        .record_failure(services::run_state::LoaderOutcome::FetchFailure);
                    None
                }
            }
        }
        .instrument(span)
        .await
    };

    if let Some(manifest) = versions {
        if cfg!(feature = "fabric") {
            let span = tracing::info_span!("fabric_processing");
            async {
                match FABRIC_BREAKER.call(async {
                    fabric::retrieve_data(
                        &manifest,
                        &uploader,
                        &manifest_builder,
                        &CLIENT,
                        semaphore.clone(),
                    )
                    .await
                })
                .await
                {
                    Ok(_) => info!("Fabric processing completed"),
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                        warn!("Fabric circuit breaker is open, skipping");
                        run_state
                            .loader_mut("fabric")
                            .record_failure(services::run_state::LoaderOutcome::CircuitOpen);
                    }
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                        error!(error = %err, "Fabric processing failed");
                        run_state
                            .loader_mut("fabric")
                            .record_failure(services::run_state::LoaderOutcome::FetchFailure);
                    }
                }
            }
            .instrument(span)
            .await;
        }

        if cfg!(feature = "forge") {
            let span = tracing::info_span!("forge_processing");
            async {
                match FORGE_BREAKER.call(async {
                    forge::retrieve_data(
                        &manifest,
                        &uploader,
                        &manifest_builder,
                        &CLIENT,
                        semaphore.clone(),
                    )
                    .await
                })
                .await
                {
                    Ok(_) => info!("Forge processing completed"),
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                        warn!("Forge circuit breaker is open, skipping");
                        run_state
                            .loader_mut("forge")
                            .record_failure(services::run_state::LoaderOutcome::CircuitOpen);
                    }
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                        error!(error = %err, "Forge processing failed");
                        run_state
                            .loader_mut("forge")
                            .record_failure(services::run_state::LoaderOutcome::FetchFailure);
                    }
                }
            }
            .instrument(span)
            .await;
        }

        if cfg!(feature = "quilt") {
            let span = tracing::info_span!("quilt_processing");
            async {
                match QUILT_BREAKER.call(async {
                    quilt::retrieve_data(
                        &manifest,
                        &uploader,
                        &manifest_builder,
                        &CLIENT,
                        semaphore.clone(),
                    )
                    .await
                })
                .await
                {
                    Ok(_) => info!("Quilt processing completed"),
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                        warn!("Quilt circuit breaker is open, skipping");
                        run_state
                            .loader_mut("quilt")
                            .record_failure(services::run_state::LoaderOutcome::CircuitOpen);
                    }
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                        error!(error = %err, "Quilt processing failed");
                        run_state
                            .loader_mut("quilt")
                            .record_failure(services::run_state::LoaderOutcome::FetchFailure);
                    }
                }
            }
            .instrument(span)
            .await;
        }

        if cfg!(feature = "neoforge") {
            let span = tracing::info_span!("neoforge_processing");
            async {
                match NEOFORGE_BREAKER.call(async {
                    neoforge::retrieve_data(
                        &manifest,
                        &uploader,
                        &manifest_builder,
                        &CLIENT,
                        semaphore.clone(),
                    )
                    .await
                })
                .await
                {
                    Ok(_) => info!("NeoForge processing completed"),
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Open) => {
                        warn!("NeoForge circuit breaker is open, skipping");
                        run_state
                            .loader_mut("neoforge")
                            .record_failure(services::run_state::LoaderOutcome::CircuitOpen);
                    }
                    Err(crate::infrastructure::circuit_breaker::CircuitBreakerError::Failed(err)) => {
                        error!(error = %err, "NeoForge processing failed");
                        run_state
                            .loader_mut("neoforge")
                            .record_failure(services::run_state::LoaderOutcome::FetchFailure);
                    }
                }
            }
            .instrument(span)
            .await;
        }

        // All CAS objects have been uploaded immediately during processing.
        // Now we upload the loader manifests and root manifest atomically.
        // A single shared `cycle_uploaded_paths` collects every path uploaded by
        // this cycle's manifest writes so we can purge them from the CDN below.
        let timestamp = services::cas::now_timestamp();
        let cycle_uploaded_paths: Arc<tokio::sync::Mutex<Vec<String>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // Seed `loader_references` from the PREVIOUSLY-published root manifest so
        // any loader whose manifest upload fails this cycle stays referenced at
        // its last known-good timestamp. Otherwise a single Forge S3 failure
        // would silently drop Forge from the published root manifest (clients
        // would stop seeing Forge support entirely), which directly violates
        // the "if Forge breaks, everything else keeps updating" contract.
        let previous_root = fetch_previous_root_manifest().await;
        // A transiently-unreadable previous root means the carry-forward seed
        // can't be trusted, so this cycle must not repoint the root (see the
        // root-publish guard below). Loader manifests are still built and
        // uploaded; only the atomic root commit is held back.
        let previous_root_unreadable =
            matches!(previous_root, PreviousRoot::Unreadable);
        let previous_root_manifest: Option<services::cas::RootManifest> =
            match previous_root {
                PreviousRoot::Loaded(m) => Some(m),
                PreviousRoot::Absent | PreviousRoot::Unreadable => None,
            };
        let mut loader_references: std::collections::BTreeMap<
            String,
            services::cas::LoaderReference,
        > = previous_root_manifest
            .as_ref()
            .map(|r| r.loaders.clone())
            .unwrap_or_default();
        // The untouched carry-forward seed. Fresh uploads overwrite entries in
        // `loader_references` as they succeed, so when a pin later fails
        // verification the value sitting in the map is the FRESH build — the
        // one the operator pinned away from. Restoration must come from here.
        let carry_forward_references = loader_references.clone();
        let mut upload_failures: Vec<String> = Vec::new();

        // §1.6: load pins once per cycle from S3. A 404 means no pins are
        // active; a transient fetch error or a parse failure is "unknown pin
        // state" and holds back the root publish (below) rather than silently
        // dropping an active pin. (run-state was loaded at the top of the cycle
        // so retrieval-phase outcomes could be recorded.)
        let (pins, pins_unreadable) =
            match services::pins::load_checked(&CLIENT).await {
                services::pins::PinsLoad::Loaded(pins) => (pins, false),
                services::pins::PinsLoad::Unreadable => {
                    (services::pins::Pins::new(), true)
                }
            };

        // §1.6: Warn about pins that have been active for too long so
        // they aren't silently forgotten (the DiscordTracingLayer forwards
        // warn! events automatically).
        services::pins::warn_stale_pins(
            &pins,
            chrono::Duration::hours(PIN_STALE_THRESHOLD_HOURS),
        );

        let all_loaders = manifest_builder.get_loaders();
        info!(
            loader_count = all_loaders.len(),
            "Building loader manifests"
        );

        for loader in &all_loaders {
            if let Some(loader_manifest) =
                manifest_builder.build_loader_manifest(loader)
            {
                let manifest_path = format!(
                    "v{}/manifests/{}/{}.json",
                    crate::services::cas::CAS_VERSION,
                    loader,
                    loader_manifest.timestamp
                );

                info!(
                    loader = %loader,
                    version_count = loader_manifest.versions.as_array().map(|a| a.len()).unwrap_or(0),
                    path = %manifest_path,
                    "Uploading loader manifest"
                );

                // §1.1: Fetch the previous loader manifest for this loader (if
                // any) and run the sanity gate before uploading.
                let previous_loader_manifest: Option<
                    services::cas::LoaderManifest,
                > = if let Some(prev_ref) = previous_root_manifest
                    .as_ref()
                    .and_then(|r| r.loaders.get(loader.as_str()))
                {
                    // Read the sanity-gate baseline from S3, not the CDN, for the
                    // same read-after-write reason as the root manifest above —
                    // `prev_ref.url` is the relative S3 key for the manifest.
                    //
                    // A 404 means there is genuinely no baseline yet, so the gate
                    // is skipped (nothing to compare against). A transient fetch
                    // error or a parse failure is different: skipping the gate
                    // there would let an unverified — possibly collapsed —
                    // manifest publish. In that case keep the previous reference
                    // live through carry-forward (the seed already holds it) and
                    // skip this loader's upload, retrying next cycle.
                    match CLIENT.get_object(&prev_ref.url).await {
                        Ok(resp) => match serde_json::from_slice::<
                            services::cas::LoaderManifest,
                        >(resp.bytes())
                        {
                            Ok(manifest) => Some(manifest),
                            Err(e) => {
                                error!(loader = %loader, error = %e, "Previous loader manifest exists but could not be parsed; keeping the carry-forward reference and skipping this loader's upload rather than bypassing the sanity gate");
                                run_state.loader_mut(loader).record_failure(
                                    services::run_state::LoaderOutcome::FetchFailure,
                                );
                                continue;
                            }
                        },
                        Err(s3::error::S3Error::Http(404, _)) => None,
                        Err(e) => {
                            error!(loader = %loader, error = %e, "Failed to fetch previous loader manifest from S3; keeping the carry-forward reference and skipping this loader's upload rather than bypassing the sanity gate");
                            run_state.loader_mut(loader).record_failure(
                                services::run_state::LoaderOutcome::FetchFailure,
                            );
                            continue;
                        }
                    }
                } else {
                    None
                };

                // Run the sanity gate (pure function — no I/O).
                match services::sanity::check_loader_health(
                    loader,
                    &loader_manifest,
                    previous_loader_manifest.as_ref(),
                ) {
                    Ok(()) => {
                        // Gate passed — proceed with upload.
                    }
                    Err(violation) => {
                        // §1.1: Gate tripped. Skip this loader's upload for
                        // this cycle. The carry-forward in `loader_references`
                        // (seeded from the previous root manifest above) keeps
                        // the previous reference live — no extra work needed.
                        error!(
                            loader = %loader,
                            violation = %violation,
                            "Sanity gate tripped — skipping upload; previous manifest kept live in root"
                        );
                        // §1.4: Record outcome.
                        run_state.loader_mut(loader)
                            .record_failure(services::run_state::LoaderOutcome::SanityGateBlocked);
                        continue;
                    }
                }

                match serde_json::to_vec_pretty(&loader_manifest) {
                    Ok(manifest_bytes) => {
                        match upload_file_to_bucket(
                            manifest_path.clone(),
                            manifest_bytes,
                            Some("application/json".to_string()),
                            cycle_uploaded_paths.clone(),
                            semaphore.clone(),
                        )
                        .await
                        {
                            Ok(_) => {
                                info!(loader = %loader, "Loader manifest uploaded successfully");

                                // §1.4: Record successful build.
                                run_state.loader_mut(loader).record_success(
                                    &loader_manifest.timestamp,
                                    &manifest_path,
                                );

                                // §1.6: Record the fresh build's timestamp in
                                // the root reference. Pins are applied uniformly
                                // after the loop (see below) so they also cover
                                // loaders whose fresh build tripped the sanity
                                // gate, failed to upload, or was circuit-open.
                                loader_references.insert(
                                    loader.clone(),
                                    services::cas::LoaderReference::new(
                                        loader,
                                        loader_manifest.timestamp.clone(),
                                    ),
                                );
                            }
                            Err(e) => {
                                error!(loader = %loader, error = %e, "Failed to upload loader manifest; keeping previous reference if any");
                                upload_failures.push(loader.clone());
                                // §1.4: Record fetch/upload failure.
                                run_state.loader_mut(loader)
                                    .record_failure(services::run_state::LoaderOutcome::FetchFailure);
                            }
                        }
                    }
                    Err(e) => {
                        error!(loader = %loader, error = %e, "Failed to serialize loader manifest; keeping previous reference if any");
                        upload_failures.push(loader.clone());
                        run_state.loader_mut(loader).record_failure(
                            services::run_state::LoaderOutcome::FetchFailure,
                        );
                    }
                }
            }
        }

        if !upload_failures.is_empty() {
            warn!(
                loaders = ?upload_failures,
                "Some loader manifests failed to upload this cycle; their previous references stay live in the root manifest"
            );
        }

        // §1.6: Apply pins uniformly. A pinned loader's root reference always
        // uses `pinned_to`, regardless of whether this cycle's fresh build
        // succeeded, tripped the sanity gate, failed to upload, or was
        // circuit-open. Only the root pointer is overridden; any fresh manifest
        // that was built and passed its gate this cycle is still uploaded above
        // for inspection. This matches the documented pin contract in
        // services/pins.rs.
        //
        // The pinned manifest is verified to exist on S3 first: a pin pointing
        // at a timestamp that isn't there (operator typo, or history that was
        // pruned) would otherwise publish a root referencing a 404, silently
        // dropping that loader for every client. On a missing or unverifiable
        // target the pin is skipped — the carry-forward reference is kept — and
        // a loud error is logged for an operator to correct.
        // A pin that can't be verified must not let this cycle's fresh build
        // through: on fresh-success cycles the map already holds the fresh
        // reference, which is exactly the build the operator pinned away
        // from. Restore the previous root's reference (in steady state, the
        // pinned build itself); a pinned loader with no previous reference
        // publishes nothing rather than the pinned-away-from build.
        fn restore_carry_forward(
            references: &mut std::collections::BTreeMap<
                String,
                services::cas::LoaderReference,
            >,
            carry_forward: &std::collections::BTreeMap<
                String,
                services::cas::LoaderReference,
            >,
            loader: &str,
        ) {
            match carry_forward.get(loader) {
                Some(previous) => {
                    references.insert(loader.to_string(), previous.clone());
                }
                None => {
                    references.remove(loader);
                }
            }
        }

        for (loader, pin) in pins.iter() {
            let pinned_ref = services::cas::LoaderReference::new(
                loader,
                pin.pinned_to.clone(),
            );
            match CLIENT.head_object(&pinned_ref.url).await {
                Ok(_) => {
                    info!(
                        loader = %loader,
                        pinned_to = %pin.pinned_to,
                        reason = %pin.reason,
                        "Loader is pinned — root manifest references the pinned timestamp"
                    );
                    loader_references.insert(loader.clone(), pinned_ref);
                }
                Err(s3::error::S3Error::Http(404, _)) => {
                    error!(
                        loader = %loader,
                        pinned_to = %pin.pinned_to,
                        path = %pinned_ref.url,
                        "Pinned loader manifest does not exist on S3 — refusing to publish a dangling root reference; restoring the previous root's reference and leaving the pin in place for an operator to correct"
                    );
                    restore_carry_forward(
                        &mut loader_references,
                        &carry_forward_references,
                        loader,
                    );
                }
                Err(e) => {
                    error!(
                        loader = %loader,
                        pinned_to = %pin.pinned_to,
                        path = %pinned_ref.url,
                        error = %e,
                        "Failed to verify pinned loader manifest on S3 — restoring the previous root's reference for this cycle"
                    );
                    restore_carry_forward(
                        &mut loader_references,
                        &carry_forward_references,
                        loader,
                    );
                }
            }
        }

        if previous_root_unreadable || pins_unreadable {
            error!(
                previous_root_unreadable,
                pins_unreadable,
                "Holding back the root manifest publish this cycle: admin state \
                 was unreadable on S3 (the previous root and/or pins.json — a \
                 transient fetch error or a parse failure). Carry-forward and pin \
                 overrides can't be guaranteed, so publishing a fresh root could \
                 silently drop a loader that lacks a fresh reference or republish a \
                 build an operator pinned away from. Loader manifests built this \
                 cycle were still uploaded; the existing root stays live and will \
                 be repointed next cycle."
            );
        } else if !loader_references.is_empty() {
            let root_manifest =
                services::cas::RootManifest::new(loader_references);
            let root_path =
                format!("v{}/manifest.json", crate::services::cas::CAS_VERSION);

            info!("Uploading root manifest (atomic commit point)");

            match serde_json::to_vec_pretty(&root_manifest) {
                Ok(root_bytes) => {
                    // Write history backup FIRST so it always
                    // covers any root we publish — previously
                    // the backup ran after the root, leaving
                    // a published manifest with no history
                    // entry if the process was killed in
                    // between.
                    let backup_path = format!(
                        "v{}/history/manifest-{}.json",
                        crate::services::cas::CAS_VERSION,
                        timestamp
                    );
                    info!(backup_path = %backup_path, "Creating backup of root manifest");
                    match upload_file_to_bucket(
                        backup_path,
                        root_bytes.clone(),
                        Some("application/json".to_string()),
                        cycle_uploaded_paths.clone(),
                        semaphore.clone(),
                    )
                    .await
                    {
                        Ok(_) => info!("Backup created successfully"),
                        Err(e) => {
                            warn!(error = %e, "Failed to create backup (non-fatal)")
                        }
                    }

                    // §1.5: Acquire the shared root-write mutex so this PUT
                    // cannot race with the control executor rollback handler
                    // writing to the same path.
                    let _root_write_guard = ROOT_WRITE_LOCK.lock().await;

                    match upload_file_to_bucket(
                        root_path.clone(),
                        root_bytes,
                        Some("application/json".to_string()),
                        cycle_uploaded_paths.clone(),
                        semaphore.clone(),
                    )
                    .await
                    {
                        Ok(_) => {
                            info!(
                                "Root manifest uploaded successfully - all changes are now live"
                            );
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to upload root manifest - changes NOT committed");
                        }
                    }

                    // Release the root-write mutex before saving run-state.
                    drop(_root_write_guard);
                }
                Err(e) => {
                    error!(error = %e, "Failed to serialize root manifest");
                }
            }

            info!("Processing cycle completed successfully");

            // Build absolute URLs from every path uploaded by this cycle.
            // (CAS objects are immutable hash-keyed and bypass this purge by
            // design — the BatchUploader path doesn't go through
            // upload_file_to_bucket. Manifests + root + backup do, and those
            // are the URLs Cloudflare needs to invalidate.)
            let uploaded_paths: Vec<String> = {
                let guard = cycle_uploaded_paths.lock().await;
                guard.clone()
            };
            let uploaded_manifest_urls: Vec<String> = uploaded_paths
                .into_iter()
                .map(|p| format!("{}/{}", crate::common::BASE_URL.as_str(), p))
                .collect();

            if !uploaded_manifest_urls.is_empty() {
                let cloudflare_enabled = dotenvy::var("CLOUDFLARE_INTEGRATION")
                    .map(|v| v == "true")
                    .unwrap_or(false);

                if cloudflare_enabled {
                    match (
                        dotenvy::var("CLOUDFLARE_TOKEN"),
                        dotenvy::var("CLOUDFLARE_ZONE_ID"),
                    ) {
                        (Ok(token), Ok(zone_id)) => {
                            match services::cloudflare::purge_cloudflare_cache(
                                &token,
                                &zone_id,
                                &uploaded_manifest_urls,
                            )
                            .await
                            {
                                Ok(_) => {
                                    info!("Cloudflare cache purge successful");
                                }
                                Err(e) => {
                                    warn!(error = %e, "Cloudflare cache purge failed, but continuing");
                                }
                            }
                        }
                        _ => {
                            warn!(
                                "CLOUDFLARE_INTEGRATION is enabled but CLOUDFLARE_TOKEN or \
                                 CLOUDFLARE_ZONE_ID is missing"
                            );
                        }
                    }
                } else {
                    info!(
                        "Cloudflare cache purging disabled (set CLOUDFLARE_INTEGRATION=true to enable)"
                    );
                }
            }

        } else {
            // No fresh loader manifests AND no carry-forward from the previous
            // root manifest — emit `error!` (not warn!) so this is visible in
            // Discord and Betterstack. Means every loader failed this cycle on
            // a brand-new deployment; clients will see no manifest at all.
            error!(
                "No loader manifests were built and no previous root manifest exists - skipping root manifest upload"
            );
        }
    }

    // §1.4: Persist run-state once at the end of the cycle — including cycles
    // where minecraft was circuit-open/failed and the publish block was
    // skipped — so the admin server always reflects the latest attempt even
    // after a process restart.
    services::run_state::save(&CLIENT, &mut run_state).await;
}

fn check_env_vars() -> bool {
    let mut failed = false;

    fn check_var<T: std::str::FromStr>(var: &str) -> bool {
        if dotenvy::var(var)
            .ok()
            .and_then(|s| s.parse::<T>().ok())
            .is_none()
        {
            warn!(
                "Variable `{}` missing in dotenvy or not of type `{}`",
                var,
                std::any::type_name::<T>()
            );
            true
        } else {
            false
        }
    }

    failed |= check_var::<String>("BASE_URL");

    failed |= check_var::<String>("S3_ACCESS_TOKEN");
    failed |= check_var::<String>("S3_SECRET");
    failed |= check_var::<String>("S3_URL");
    failed |= check_var::<String>("S3_REGION");
    failed |= check_var::<String>("S3_BUCKET_NAME");

    failed |= check_var::<String>("BRAND_NAME");
    failed |= check_var::<String>("SUPPORT_EMAIL");

    failed
}

static CLIENT: LazyLock<Bucket> = LazyLock::new(|| {
    let bucket = Bucket::new(
        &dotenvy::var("S3_BUCKET_NAME").unwrap(),
        if &*dotenvy::var("S3_REGION").unwrap() == "r2" {
            Region::R2 {
                account_id: dotenvy::var("S3_URL").unwrap(),
            }
        } else {
            Region::Custom {
                region: dotenvy::var("S3_REGION").unwrap(),
                endpoint: dotenvy::var("S3_URL").unwrap(),
            }
        },
        Credentials::new(
            Some(&*dotenvy::var("S3_ACCESS_TOKEN").unwrap()),
            Some(&*dotenvy::var("S3_SECRET").unwrap()),
            None,
            None,
            None,
        )
        .unwrap(),
    )
    .unwrap();

    bucket.with_path_style()
});

static MINECRAFT_BREAKER: LazyLock<
    crate::infrastructure::circuit_breaker::CircuitBreaker,
> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new(
        "minecraft",
        CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        Duration::from_secs(CIRCUIT_BREAKER_RESET_TIMEOUT_SECS),
    )
});

static FORGE_BREAKER: LazyLock<
    crate::infrastructure::circuit_breaker::CircuitBreaker,
> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new(
        "forge",
        CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        Duration::from_secs(CIRCUIT_BREAKER_RESET_TIMEOUT_SECS),
    )
});

static FABRIC_BREAKER: LazyLock<
    crate::infrastructure::circuit_breaker::CircuitBreaker,
> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new(
        "fabric",
        CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        Duration::from_secs(CIRCUIT_BREAKER_RESET_TIMEOUT_SECS),
    )
});

static QUILT_BREAKER: LazyLock<
    crate::infrastructure::circuit_breaker::CircuitBreaker,
> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new(
        "quilt",
        CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        Duration::from_secs(CIRCUIT_BREAKER_RESET_TIMEOUT_SECS),
    )
});

static NEOFORGE_BREAKER: LazyLock<
    crate::infrastructure::circuit_breaker::CircuitBreaker,
> = LazyLock::new(|| {
    crate::infrastructure::circuit_breaker::CircuitBreaker::new(
        "neoforge",
        CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        Duration::from_secs(CIRCUIT_BREAKER_RESET_TIMEOUT_SECS),
    )
});

#[instrument(skip(bytes, uploaded_files, semaphore), fields(size = bytes.len()))]
pub async fn upload_file_to_bucket(
    path: String,
    bytes: Vec<u8>,
    content_type: Option<String>,
    uploaded_files: Arc<tokio::sync::Mutex<Vec<String>>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    info!(path = %path, "Started uploading");

    // Acquire the upload permit INSIDE each retry attempt rather than holding
    // it for the whole retry sequence (up to 5 × 60s). The previous design
    // could deadlock the pool: all MAX_CONCURRENT_UPLOADS permits held by
    // retrying uploaders, waiting on downloaders waiting on permits.
    (|| async {
        let _permit = semaphore.acquire().await?;
        let key = path.clone();

        let result = if let Some(ref content_type) = content_type {
            CLIENT
                .put_object_with_content_type(key.clone(), &bytes, content_type)
                .await
        } else {
            CLIENT.put_object(key.clone(), &bytes).await
        }
        .map_err(|err| {
            error!(path = %path, error = %err, "Failed to upload");
            crate::infrastructure::error::s3_error(err, path.clone())
        });

        match result {
            Ok(_) => {
                {
                    let mut uploaded_files = uploaded_files.lock().await;
                    uploaded_files.push(key);
                }
                info!(path = %path, "Upload completed");

                Ok(())
            }
            Err(err) => {
                error!(path = %path, error = %err, "Upload failed");
                Err(err)
            }
        }
    })
    .retry(
        ExponentialBuilder::default()
            .with_max_times(MAX_UPLOAD_RETRIES)
            .with_max_delay(Duration::from_secs(MAX_RETRY_DELAY_SECS)),
    )
    .when(|e: &crate::infrastructure::error::Error| e.should_retry())
    .await
}

pub fn format_url(path: &str) -> String {
    let full_url = format!("{}/{}", crate::common::BASE_URL.as_str(), path);
    info!(path = %path, url = %full_url, "Formatted URL");
    full_url
}

pub use services::download::{download_file, download_file_mirrors};

/// Outcome of reading the previously-published root manifest at the start of a
/// publish cycle.
enum PreviousRoot {
    /// The root was read and parsed; seed carry-forward and sanity baselines
    /// from it.
    Loaded(services::cas::RootManifest),
    /// No root exists yet (404) — a genuine cold start / first deploy.
    Absent,
    /// The root exists but could not be fetched (transient error) or parsed.
    /// Carry-forward can't be trusted this cycle.
    Unreadable,
}

/// Fetch the previously-published root manifest so we can carry forward loader
/// references on partial-failure cycles.
///
/// Distinguishes a genuine cold start (404 → `Absent`) from a root that exists
/// but couldn't be fetched or parsed (`Unreadable`). The latter must NOT be
/// treated as a cold start: that empties the carry-forward seed, and any loader
/// that gate-blocks, fails to upload, or is circuit-open this cycle would then
/// be dropped from the freshly-published root entirely.
async fn fetch_previous_root_manifest() -> PreviousRoot {
    let root_path =
        format!("v{}/manifest.json", crate::services::cas::CAS_VERSION);
    // Read from S3 (the authoritative store, with read-after-write consistency)
    // rather than the CDN. A just-purged Cloudflare edge can still serve the
    // pre-publish or pre-rollback root for the cache TTL, which would seed
    // carry-forward and the sanity baseline from a stale manifest.
    match CLIENT.get_object(&root_path).await {
        Ok(resp) => {
            match serde_json::from_slice::<services::cas::RootManifest>(
                resp.bytes(),
            ) {
                Ok(m) => {
                    info!(
                        loader_count = m.loaders.len(),
                        "Loaded previous root manifest from S3 for carry-forward"
                    );
                    PreviousRoot::Loaded(m)
                }
                Err(e) => {
                    error!(error = %e, "Previous root manifest exists but couldn't parse; holding back the root publish this cycle to avoid dropping loaders");
                    PreviousRoot::Unreadable
                }
            }
        }
        Err(s3::error::S3Error::Http(404, _)) => {
            info!(path = %root_path, "No previous root manifest on S3 (first deploy?)");
            PreviousRoot::Absent
        }
        Err(e) => {
            error!(error = %e, "Failed to fetch previous root manifest from S3; holding back the root publish this cycle to avoid dropping loaders");
            PreviousRoot::Unreadable
        }
    }
}

#[instrument(skip(uploaded_files, semaphore))]
pub async fn upload_static_files(
    uploaded_files: Arc<tokio::sync::Mutex<Vec<String>>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    use path_slash::PathExt as _;
    let cdn_upload_dir =
        dotenvy::var("CDN_UPLOAD_DIR").unwrap_or("./upload_cdn".to_string());

    info!(dir = %cdn_upload_dir, "Uploading static files");

    if !std::path::Path::new(&cdn_upload_dir).exists() {
        // Returning Err lets the caller decide; main.rs treats this as
        // non-fatal so the hourly loop still services Forge/etc. updates
        // even if the bootstrap static-files directory is missing.
        return Err(crate::infrastructure::error::invalid_input(format!(
            "CDN_UPLOAD_DIR '{cdn_upload_dir}' does not exist; skipping static files upload"
        )));
    }

    for entry in walkdir::WalkDir::new(&cdn_upload_dir) {
        let entry = entry.map_err(|e| {
            crate::infrastructure::error::ErrorKind::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to walk directory: {}", e),
            ))
        })?;
        if entry.path().is_file() {
            let upload_path = entry.path()
                .strip_prefix(&cdn_upload_dir)
                .expect("Unwrap to be safe because we are striping the prefix to the directory walked")
                 .to_slash()
                .ok_or_else(|| {
                    crate::infrastructure::error::invalid_input(format!(
                        "Failed to convert path to utf8 string {}",
                        entry.path().display()
                    ))
                })?;

            if upload_path.ends_with(".DS_Store") {
                continue;
            }

            info!(
                file = %entry.path().display(),
                cdn_path = %upload_path,
                "Uploading static file to CDN"
            );

            let content_type =
                match entry.path().extension().and_then(OsStr::to_str) {
                    Some("json") => Some("application/json".to_string()),
                    Some("jar") => Some("application/java-archive".to_string()),
                    _ => None,
                };

            upload_file_to_bucket(
                upload_path.to_string(), // NOTE: if path is non utf8 this will not be a pretty path
                std::fs::read(entry.path())?,
                content_type,
                uploaded_files.clone(),
                semaphore.clone(),
            )
            .await?;
        }
    }
    Ok(())
}
