# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.9] - 2026-01-05

### Changed
- `Bot` struct now uses `AbortHandle` instead of `JoinHandle` for the refresh task. This makes `Bot` both `Send` and `Sync`, allowing safe sharing across threads with `Arc<Bot>`.
- `cancel_refresh_task` is no longer async.

### Fixed
- `impl Drop for Bot` - the refresh task is now automatically aborted when `Bot` is dropped, preventing resource leaks.
- Fixed README examples: corrected import paths, added missing imports, fixed `refresh()` method signature.
