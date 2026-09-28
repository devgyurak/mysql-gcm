# third_party

Vendored, pinned dependencies. Nothing here is edited locally; bumping a version means replacing the
file and recording the new digest below.

| Path | Version | License | SHA-256 |
|---|---|---|---|
| `nlohmann/json.hpp` | 3.11.3 | MIT | `9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6` |

`nlohmann/json.hpp` is used by `tests/unit` only, to read `spec/test-vectors.json`. It is never
linked into the component: `src/` has no third-party dependency beyond the server's own OpenSSL.
