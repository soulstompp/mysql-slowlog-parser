# Changelog

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
