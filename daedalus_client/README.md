# Daedalus Client

Daedalus Client is a Rust-based metadata processing and distribution system for Minecraft launchers. It fetches, processes, and uploads version metadata for vanilla Minecraft and popular mod loaders (Forge, Fabric, Quilt, NeoForge) using a Content-Addressable Storage (CAS) architecture.

## Features

- **Content-Addressable Storage (CAS)**: Files stored by SHA256 hash for deduplication and immutability
- **Unified Versioning**: Single version entrypoint (v3) for all metadata types
- **Multi-Loader Support**: Minecraft, Forge, Fabric, Quilt, and NeoForge
- **S3-Compatible Storage**: Works with AWS S3, Cloudflare R2, and other S3-compatible services
- **Atomic Updates**: Root manifest provides atomic switching between versions
- **Rollback Support**: Historical manifests enable auditing and rollback capabilities
- **Cloudflare Integration**: Optional cache purging on updates
- **Observability**: Structured logging with Sentry error tracking and Betterstack integration

## Architecture

The CAS architecture provides several key benefits:

```
Root Manifest (v3/manifest.json)
  ├─> minecraft manifest (v3/manifests/minecraft/<timestamp>.json)
  ├─> forge manifest (v3/manifests/forge/<timestamp>.json)
  ├─> fabric manifest (v3/manifests/fabric/<timestamp>.json)
  ├─> quilt manifest (v3/manifests/quilt/<timestamp>.json)
  └─> neoforge manifest (v3/manifests/neoforge/<timestamp>.json)

Each loader manifest contains:
  ├─> version entries with content hashes
  └─> references to v3/objects/<hash[0..2]>/<hash[2..]>
```

**Benefits:**
- **Atomic updates**: Single root manifest update makes all changes visible
- **Rollback**: Keep historical manifests, update root to point to previous version
- **Deduplication**: Same content = same hash = stored once
- **Immutability**: Content never changes, only manifest pointers

## Requirements

- **Rust**: 1.85 or later (Rust 2024 edition)
- **S3-Compatible Storage**: AWS S3, Cloudflare R2, MinIO, etc.
- **Environment Variables**: See configuration below

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd daedalus/daedalus_client
```

2. Build the project:
```bash
cargo build --release
```

3. Create a `.env` file with required configuration (see Environment Variables below)

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BASE_URL` | Base URL for CAS objects (public CDN URL) | `https://cdn.example.com` |
| `SENTRY_DSN` | Sentry error tracking DSN | `https://key@sentry.io/project` |
| `BRAND_NAME` | Brand name for metadata | `MyLauncher` |
| `SUPPORT_EMAIL` | Support email for metadata | `support@example.com` |
| `S3_BUCKET_NAME` | S3 bucket name | `minecraft-metadata` |
| `S3_REGION` | S3 region (use `r2` for Cloudflare R2) | `us-east-1` or `r2` |
| `S3_URL` | S3 endpoint URL | `https://s3.amazonaws.com` or `https://<account>.r2.cloudflarestorage.com` |
| `S3_ACCESS_TOKEN` | S3 access key ID | `AKIAIOSFODNN7EXAMPLE` |
| `S3_SECRET` | S3 secret access key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |

### Optional Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LOG_FORMAT` | Log output format | `text` | `json` or `text` |
| `RUST_LOG` | Rust log level filter | `info` | `debug`, `info`, `warn`, `error` |
| `BETTERSTACK_TOKEN` | Betterstack logging token | None | `your-betterstack-token` |
| `CLOUDFLARE_INTEGRATION` | Enable Cloudflare cache purging | `false` | `true` or `false` |
| `CLOUDFLARE_TOKEN` | Cloudflare API token (required if integration enabled) | None | `your-cloudflare-token` |
| `CLOUDFLARE_ZONE_ID` | Cloudflare zone ID (required if integration enabled) | None | `your-zone-id` |
| `CDN_UPLOAD_DIR` | Local directory for CDN file uploads | `./upload_cdn` | `/path/to/cdn/dir` |
| `FORCE_REPROCESS` | Force reprocessing of all NeoForge versions | `false` | `true` or `false` |

### Example .env File

```env
# Required Configuration
BASE_URL=https://cdn.example.com
SENTRY_DSN=https://key@sentry.io/project
BRAND_NAME=MyLauncher
SUPPORT_EMAIL=support@example.com

# S3 Configuration
S3_BUCKET_NAME=minecraft-metadata
S3_REGION=us-east-1
S3_URL=https://s3.amazonaws.com
S3_ACCESS_TOKEN=your-access-key
S3_SECRET=your-secret-key

# Optional: Logging
LOG_FORMAT=json
RUST_LOG=info
BETTERSTACK_TOKEN=your-betterstack-token

# Optional: Cloudflare Integration
CLOUDFLARE_INTEGRATION=true
CLOUDFLARE_TOKEN=your-cloudflare-token
CLOUDFLARE_ZONE_ID=your-zone-id
```

### Example .env File for Cloudflare R2

```env
# Required Configuration
BASE_URL=https://pub-abc123.r2.dev
SENTRY_DSN=https://key@sentry.io/project
BRAND_NAME=MyLauncher
SUPPORT_EMAIL=support@example.com

# Cloudflare R2 Configuration
S3_BUCKET_NAME=minecraft-metadata
S3_REGION=r2
S3_URL=https://abc123.r2.cloudflarestorage.com
S3_ACCESS_TOKEN=your-r2-access-key
S3_SECRET=your-r2-secret-key

# Optional: Cloudflare Integration
CLOUDFLARE_INTEGRATION=true
CLOUDFLARE_TOKEN=your-cloudflare-token
CLOUDFLARE_ZONE_ID=your-zone-id
```

## Usage

### Run Full Metadata Processing

Process all enabled loaders (default: minecraft, forge, fabric, quilt, neoforge):

```bash
cargo run --release
```

### Run Specific Loaders Only

Use feature flags to enable specific loaders:

```bash
# Only Minecraft and Fabric
cargo run --release --no-default-features --features fabric

# Only Forge
cargo run --release --no-default-features --features forge

# Minecraft, Fabric, and Quilt
cargo run --release --no-default-features --features fabric,quilt
```

### Development Mode

Run with debug logging:

```bash
RUST_LOG=debug cargo run
```

### Force Reprocess

Force reprocessing of all versions (useful for NeoForge):

```bash
FORCE_REPROCESS=true cargo run --release
```

## Output Structure

The client generates the following structure in your S3 bucket:

```
v3/
├── manifest.json                              # Root manifest (atomic pointer)
├── manifests/
│   ├── minecraft/<timestamp>.json             # Minecraft version manifest
│   ├── forge/<timestamp>.json                 # Forge version manifest
│   ├── fabric/<timestamp>.json                # Fabric version manifest
│   ├── quilt/<timestamp>.json                 # Quilt version manifest
│   └── neoforge/<timestamp>.json              # NeoForge version manifest
├── objects/
│   └── <hash[0..2]>/
│       └── <hash[2..]>                        # Content-addressed files
└── history/
    └── manifest-<timestamp>.json              # Historical root manifests
```

## Testing

Run the test suite:

```bash
cargo test --all-features
```

Run tests for specific loaders:

```bash
cargo test --features forge
cargo test --features fabric,quilt
```

## Code Quality

Check code quality with Clippy:

```bash
cargo clippy --all-features
```

## Features

The following features can be enabled/disabled:

| Feature | Description | Default |
|---------|-------------|---------|
| `sentry` | Sentry error tracking | ✓ |
| `forge` | Forge loader support | ✓ |
| `fabric` | Fabric loader support | ✓ |
| `quilt` | Quilt loader support | ✓ |
| `neoforge` | NeoForge loader support | ✓ |

## Performance

- **Concurrent Processing**: Parallel version processing with configurable semaphore limits
- **Deduplication**: Lock-free artifact deduplication using DashMap
- **Batch Uploads**: Atomic batch uploads to S3 minimize requests
- **Circuit Breaker**: Resilient HTTP requests with automatic retry and backoff

## Observability

### Structured Logging

The client supports both text and JSON logging formats:

```bash
# Human-readable text logs (default)
LOG_FORMAT=text cargo run

# JSON logs for log aggregation
LOG_FORMAT=json cargo run
```

### Error Tracking

Sentry integration provides:
- Error capture and aggregation
- Release tracking
- Environment tagging

### Betterstack Integration

Optional Betterstack logging for centralized log management:

```bash
BETTERSTACK_TOKEN=your-token cargo run
```

## Troubleshooting

### S3 Connection Issues

- Verify `S3_URL`, `S3_ACCESS_TOKEN`, and `S3_SECRET` are correct
- For Cloudflare R2, ensure `S3_REGION=r2`
- Check bucket permissions for read/write access

### Cloudflare Cache Not Purging

- Verify `CLOUDFLARE_INTEGRATION=true`
- Check `CLOUDFLARE_TOKEN` has cache purge permissions
- Ensure `CLOUDFLARE_ZONE_ID` matches your domain

### Missing Versions

- Check source API availability (meta.fabricmc.net, maven.minecraftforge.net, etc.)
- Review logs for download failures
- Try `FORCE_REPROCESS=true` for NeoForge

## License

This project is part of the daedalus ecosystem for Minecraft launcher metadata management.

## Contributing

1. Ensure code passes `cargo clippy --all-features`
2. Run `cargo test --all-features` before submitting
3. Follow existing code style and architecture patterns
4. Update documentation for new features or changes
