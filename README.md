<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Transform agent</h3>

<p align="center">Rule-based request and response header rewriting, matched on path, method, headers and query, with values interpolated from the request.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-transform/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-transform/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/transform/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The agent reads a YAML or JSON file of rules. On each request it takes the
first enabled rule (highest `priority` first) whose matchers all pass, sets
and removes request headers, and remembers the rule so the same rule's
response section can set and remove response headers. A rule that fails to
apply lets the request through unchanged; if the agent is unreachable, the
filter's `failure-mode` decides.

What works today, checked end to end against `zentinel`: request and response
header `set` / `add` / `remove`, all matchers except `body`, interpolation,
and the debug headers. What does **not** work yet is listed under
[Limitations](#limitations): URL rewriting, body transformation, method and
status overrides, and response-only rules.

## Quick start

```bash
zentinel bundle install transform

cat > transform.yaml <<'EOF'
version: "1"
rules:
  - name: api-headers
    match:
      path:
        pattern: "^/api/(?P<resource>[^/]+)"
        type: regex
    request:
      headers:
        set:
          - name: X-Resource
            value: "${resource}"
        remove:
          - X-Debug
    response:
      headers:
        set:
          - name: X-Content-Type-Options
            value: nosniff
        remove:
          - Server
EOF

zentinel-transform-agent --config transform.yaml --validate
zentinel-transform-agent --config transform.yaml --grpc-address 127.0.0.1:50051
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

agents {
    agent "transform" type="custom" {
        grpc "http://127.0.0.1:50051"
        events "request_headers" "response_headers"
        timeout-ms 100
    }
}

filters {
    filter "transform" {
        type "agent"
        agent "transform"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "transform"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

Release 0.4.0 listens on gRPC only. `main` adds `--socket` for a Unix
socket (then use `unix-socket "/var/run/zentinel/transform.sock"` in the
agent block).

## Install

```bash
zentinel bundle install transform
```

Or from the repository (the crate is not on crates.io):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-transform
```

Release binaries (`zentinel-transform-agent-<version>-<platform>.tar.gz`) for
`linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are on the
[releases page](https://github.com/zentinelproxy/zentinel-agent-transform/releases).
From source: `cargo build --release`.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `--config`, `-c` | none (no rules) | Rules file; `.yaml`/`.yml` is read as YAML, anything else as JSON |
| `--grpc-address` / `TRANSFORM_GRPC_ADDRESS` | `0.0.0.0:50051` | gRPC listen address |
| `--socket`, `-s` / `TRANSFORM_SOCKET` | none | Listen on a Unix socket instead of gRPC (`main` only, unreleased) |
| `--validate` | | Parse the file, compile the patterns and exit |
| `--example-config` | | Print an example file and exit |
| `--log-level` | `info` | Log level (`RUST_LOG` takes precedence) |
| `--json-logs` | `false` | JSON log output |
| `--template-dir` | `/etc/zentinel/templates` | Overrides `settings.template_dir` (templates are not applied, see below) |

The default listen address is all interfaces; bind it to `127.0.0.1` unless
the proxy runs on another host. The file is read once at startup. The proxy
does not forward an agent block's `config { }` to the agent, so use the file.

### Settings

| Key | Default | Meaning |
|---|---|---|
| `settings.debug_headers` | `false` | Add `X-Transform-Rule` and `X-Transform-Time` to the response |
| `settings.max_body_size` | `10485760` | Body size the agent advertises to the proxy |
| `settings.timeout_ms` | `100` | Processing time the agent advertises to the proxy |

### Rules

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Rule name, used in logs and `X-Transform-Rule` |
| `enabled` | `true` | Skip the rule when `false` |
| `priority` | `50` | Higher is tried first; the first matching rule wins |
| `match.path` | any | `pattern` plus `type`: `regex` (default; numbered and named captures), `exact` or `glob` (Rust `glob` syntax, `*` also matches `/`) |
| `match.methods` | any | List of methods |
| `match.headers` | any | List of `name` plus one of `equals`, `contains`, `matches` (regex), `present: true`, `absent: true` |
| `match.query` | any | List of `name` plus `equals`, `contains` or `present: true` |
| `request.headers` | none | `set` / `add` (both overwrite) as lists of `name`/`value`, `remove` as a list of names |
| `response.headers` | none | The same, applied to the response |

Header values are interpolated: `${1}` or `${name}` for path captures,
`${request.method}`, `${request.path}`, `${request.query}`,
`${request.client_ip}`, `${request.header.<name>}`,
`${request.query_param.<name>}`, `${response.status}`,
`${response.header.<name>}`, `${correlation_id}` and `${now}` (RFC 3339). An
unknown variable becomes an empty string.

## Limitations

These keys parse and pass `--validate`, but have no effect on the request:

- `request.url` (`rewrite`, `add_query`, `remove_query`): the path is not
  rewritten. The agent sends the rewritten URL upstream in an
  `X-Original-Path` request header and the proxy routes the original path.
- `request.body` and `response.body` (`json` operations, `convert`, `clear`,
  `replace`): the new body is computed and discarded. `match.body` is only
  evaluated in that discarded body phase.
- `request.method`, `response.status`, `response.template`.
- A rule with only a `response` section never fires: the response phase runs
  only for requests where a rule with a `request` section matched.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Related

- [Registry page](https://registry.zentinelproxy.io/transform/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
