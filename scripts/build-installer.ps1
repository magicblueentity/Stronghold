param(
  [switch]$Release
)

$ErrorActionPreference = "Stop"

if ($Release) {
  cargo build --release
} else {
  cargo build
}

cargo install cargo-wix --locked
cargo wix --nocapture

Write-Host "Installer build complete. Check target\\wix\\*.msi"
