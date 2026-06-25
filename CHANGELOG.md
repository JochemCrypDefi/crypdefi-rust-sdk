# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.3.0] - 2026-01-14

### Added
- Add verification of login challenge to the login flow
- Add `CantonTopology` variant to `SignatureRequestKind`

### Changed
- Reduced the usage of owned `String` in favor of borrowed `&str` in the `Bot` public functions and internal functions

### Fixed
- Clarified the auto-refresh task log messages when the access or refresh token is missing
- Removed an unnecessary clone of the login challenge before hex decoding
- Corrected the signature buffer initialization in `Signature::to_der`

## [v0.2.0] - 2026-01-08

### Changed
- `Bot` struct now seperates between `base_url` and `signing_url` to allow customization of which AWS region is used for signing transactions. By default, the `signing_url` is set to the `base_url`
- When `signing_url` and `base_url` differ, a `/health` call is done on successfull login to the `signing_url` to initiate a TLS connection and reduce cold start latency for the first signature

## [v0.1.9] - 2026-01-05

### Changed
- `Bot` struct now uses `AbortHandle` instead of `JoinHandle` for the refresh task. This makes `Bot` both `Send` and `Sync`, allowing safe sharing across threads with `Arc<Bot>`.
- `cancel_refresh_task` is no longer async.

### Fixed
- `impl Drop for Bot` - the refresh task is now automatically aborted when `Bot` is dropped, preventing resource leaks.
- Fixed README examples: corrected import paths, added missing imports, fixed `refresh()` method signature.
