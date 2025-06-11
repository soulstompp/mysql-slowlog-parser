# Changelog

## 0.5.0 - 2025-06-11
* upgrade to winnow-datetime 0.3.0 objects
* Removed Copy trait from TimeLine and EntryCall since underlying winnow-datetime 0.3.0 objects are no longer Copy
* This is a small set of changes but it is a breaking change since the `TimeLine` and `EntryCall` objects are no longer
  Copy and the DateTime objects exposed from winnow-datetime 0.3.0 have changed. Most use-cases should not be affected.
* Allow for latest 0.7.x versions of winnow since they adhere well to semver.

## 0.4.0 - 2025-05-24
* upgrade to rust edition 2024
* fixed a warning introduced in previous release
* Update EntrySqlType to match new sqlparser AST
* upgrade bytes to 1.10.0
* upgrade futures to 0.3.31
* upgrade winnow to 0.7.10
* upgrade winnow_datetime to 0.2.3
* upgrade sqlparser to 0.56.0
* upgrade thiserror to 2.0.12
* upgrade log to 0.4.27
* upgrade tokio to 1.45.1
* upgrade tokio-util to 0.7.15

## 0.3.1 - 2025-05-13
* Upgrade of winnow-datetime crates, since older version had a bug
* Removed unused dependencies
* Upgrade of internal dependencies, sqlparser will wait for 0.4.0 since the AST is accessible to consumers.

## 0.3.0 - 2025-05-04
* Upgrade to winnow 0.7 and use ModalResult returns from parsers
* Upgrade to winnow-iso8601 0.5.0 which depends on winnow-datetime
* Return winnow-datetime 0.2.0 which will now need to be used by consumers

## 0.2.0 - 2024-11-24
* Export only DateTime types winnow-iso8601
* Changed CodecConfig to `EntryCodecConfig` so it better matches EntryCodec when exporting.
* Change type for `EntryCodecConfig.map_comment_context` to
  `Option<fn(HashMap<Bytes, Bytes>)...` so that `EntryCodecConfig` can derive `Clone`.
* Minor documentation improvements

## 0.1.0 - 2024-11-19
Initial release
