# Changelog

## 0.2.0 - 2024-11-24
* Export only DateTime types from the '
* Changed CodecConfig to `EntryCodecConfig` so it better matches EntryCodec when exporting.
* Change type for `EntryCodecConfig.map_comment_context` to
  `Option<fn(HashMap<Bytes, Bytes>)...` so that `EntryCodecConfig` can derive `Clone`.
* Minor documentation improvements

## 0.1.0 - 2024-11-19
Initial release
