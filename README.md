# TailSocks

Route traffic through any Tailscale exit node using a local SOCKS5 or HTTP proxy.

## What is TailSocks?

TailSocks creates a local SOCKS5 and/or an HTTP proxy server, automatically routing all traffic through a Tailscale exit node of your choice. This gives you the flexibility to:

- **Route specific applications** through your Tailscale network without affecting your entire system
- **Use different exit nodes** for different applications simultaneously
- **Access your Tailnet resources** from applications that support SOCKS5 or HTTP proxies
- **Bypass VPN limitations** in applications that don't support traditional VPNs

## Use Cases

- **Selective routing**: Route only specific applications (browsers, CLI tools, etc) through your Tailscale network
- **Testing**: Test how your services behave from different network locations
- **Development**: Access development resources on your Tailnet without configuring your entire system
- **Privacy**: Route sensitive traffic through your home or office network
- **Multiple exit nodes**: Run multiple instances with different exit nodes for different purposes

## Installation

### Pre-built binaries

You can download the latest version of TailSocks from the [**Releases page**](https://github.com/italypaleale/tailsocks/releases) page.

Fetch the correct archive for your system and architecture, then extract the files and copy the `tailsocks` binary to `/usr/local/bin` or another folder.

> **Mac users:** binaries are not signed by Apple and you may get a security warning when trying to run them on your Mac.
>
> To fix this, run this command: `xattr -rc path/to/tailsocks`

### Using Docker/Podman

You can run TailSocks as a Docker/Podman container. Container images are available for Linux and support amd64, arm64, and armv7/armhf.

```sh
# For podman, replace "docker run" with "podman run"
docker run \
  -d \
  --rm \
  -p 127.0.0.1:5040:5040 \
  -v tailsocks-state:/data \
  ghcr.io/italypaleale/tailsocks:1 \
  --socks-addr 0.0.0.0:5040 \
  --exit-node home-server
```

To expose the HTTP proxy too, add `-p 127.0.0.1:5041:5041` and `--http-addr 0.0.0.0:5041`.

The container's working directory is `/data`, where tsnet writes its state (`/data/tsnet-state`) by default. Mount a volume there to persist the node identity across restarts, otherwise the node re-registers each time.

> TailSocks follows semver for versioning. The command above uses the latest version in the 1.x branch. We do not publish a container image tagged "latest".

### Build from source

Using `go install`:

```sh
go install github.com/italypaleale/tailsocks@latest
```

Or clone from the Git repo:

```sh
git clone https://github.com/italypaleale/tailsocks
cd tailsocks
go build -o tailsocks
```

## Quick Start

1. **Start TailSocks with an exit node:**

   ```sh
   tailsocks --exit-node my-exit-node
   ```

   The exit node can be specified as:

     - An IP address (e.g., `100.64.1.2`)
     - A MagicDNS name (e.g., `my-exit-node`)

2. **Configure your application** to use the SOCKS5 proxy at `127.0.0.1:5040`

Your application traffic will now route through the specified Tailscale exit node.

If your application only supports HTTP proxies, start TailSocks with `--http-addr 127.0.0.1:5041` and point it there instead. See [HTTP proxy](#http-proxy) below.

## Usage

### Basic Usage

```sh
# Use a specific exit node
tailsocks --exit-node home-server

# Use a custom SOCKS5 listen address
tailsocks --exit-node home-server --socks-addr 127.0.0.1:8080

# Allow LAN access while using the exit node
tailsocks --exit-node home-server --exit-node-allow-lan-access
```

### HTTP Proxy

In addition to SOCKS5, TailSocks can expose an HTTP proxy, which is what tools that read the `http_proxy` and `https_proxy` environment variables expect. It's disabled by default, and you can enable it with the `--http-addr` (or `-p`) flag:

```sh
tailsocks --exit-node home-server --http-addr 127.0.0.1:5041
```

Then point your tools at it:

```sh
export http_proxy=http://127.0.0.1:5041
export https_proxy=http://127.0.0.1:5041
export no_proxy=localhost,127.0.0.1

# Will use your exit node's IP
curl https://api.ipify.org
```

> Note that `https_proxy` points to an `http://` URL too: HTTPS destinations are reached by opening a tunnel through the proxy with the HTTP `CONNECT` method, then negotiating TLS end-to-end with the destination. TailSocks never terminates or inspects TLS. Proxy listeners that speak TLS themselves (`https_proxy=https://…`) are not supported.

Unlike SOCKS5, an HTTP proxy always resolves destination names on the proxy side, so MagicDNS names work without any extra client configuration:

```sh
curl http://internal-service.tailnet --proxy http://127.0.0.1:5041
```

Both proxies can run at the same time and share the same exit node. To run the HTTP proxy alone, disable SOCKS5 by setting its address to an empty value:

```sh
tailsocks --exit-node home-server --http-addr 127.0.0.1:5041 --socks-addr ''
```

> **Warning:** like the SOCKS5 proxy, the HTTP proxy is not authenticated. Binding it to a non-loopback address (e.g. `0.0.0.0`) exposes an open proxy to everyone who can reach that address, and TailSocks will log a warning when you do so.

### TCP Port Forwarding

TailSocks can also forward a local TCP port to a remote host, routing the traffic through the selected exit node. This allows forwarding traffic for applications that may not support SOCKS5 proxies.

Use the `--tcp` (or `-t`) flag with a rule in the form `LISTEN=TARGET`:

```sh
# Listen on 127.0.0.1:3900 and forward to test.com:3900 through the exit node
tailsocks --exit-node home-server --tcp 127.0.0.1:3900=test.com:3900
```

- `LISTEN` is the local address to bind to, as `host:port` (e.g. `127.0.0.1:3900`). Use `:3900` or `0.0.0.0:3900` to listen on all interfaces.
- `TARGET` is the remote address to forward to, as `host:port` (e.g. `test.com:3900`). The host may be an IP address or a DNS/MagicDNS name, which is resolved through Tailscale (unless `--local-dns` is set).

The `--tcp` flag can be repeated to forward multiple ports at once:

```sh
tailsocks --exit-node home-server \
  --tcp 127.0.0.1:3900=test.com:3900 \
  --tcp 127.0.0.1:5432=db.internal:5432
```

> **Warning:** forwarded ports are not authenticated. Binding to a non-loopback address (e.g. `0.0.0.0`) exposes the forward to other hosts on your network, and TailSocks will log a warning when you do so.

### Authentication

TailSocks will use your existing Tailscale authentication. If you're not logged in, you can provide an auth key:

```sh
# Via flag
tailsocks --exit-node home-server --authkey tskey-auth-xxxxx

# Via environment variable
export TS_AUTHKEY=tskey-auth-xxxxx
tailsocks --exit-node home-server
```

If there's no existing authentication state, you will see a URL to authenticate your node in the logs.

### Authentication with OAuth2 client credentials

Alternatively to using auth keys, you can provide [OAuth2 client credentials](https://tailscale.com/kb/1215/oauth-clients) for the Tailscale control plane. These are long-lived credentials that can be used repeatedly to register multiple nodes, and each node does not require manual approval (however, if Tailnet Lock is enabled, you will need to sign each created node manually).

1. Create a new OAuth2 client:
   1. Open the [**Trust credentials**](https://login.tailscale.com/admin/settings/trust-credentials) page of the Tailscale admin console. Select the Credential button, then choose OAuth.
   2. In the list of scopes, select only **Auth keys** with **write** access. This requires the name of an ACL tag that must be used for the nodes created with the OAuth2 client.
   3. Copy both the client ID and secret.
2. Create a local file with the credentials stored in `~/.config/tailsocks/oauth2.json` (`%USERPROFILE%/.config/tailsocks/oauth2.json` on Windows) with the client ID, client secret, and name of the tag:

   ```json
   {
     "client_id": "...",
     "client_secret": "tskey-client-...",
     "tag": "tag-name"
   }
   ```

Run TailSocks with the `--oauth2` (or `-o`) option to use OAuth2 credentials:

```sh
tailsocks --exit-node home-server --oauth2
```

**Note:** when using OAuth2 credentials, nodes are registered as ephemeral by default. To make them persistent, use `--ephemeral=false`:

```sh
tailsocks --exit-node home-server --oauth2 --ephemeral=false
```

### Custom Tailscale Control Server

If you're using Headscale or another custom control server:

```sh
tailsocks --exit-node home-server --login-server https://headscale.example.com
```

## Command-Line Options

```text
Usage of tailsocks:
  -x, --exit-node string             Exit node selector: IP or MagicDNS base name (e.g. 'home-exit'). Required.
  -k, --authkey string               Optional Tailscale auth key (or set TS_AUTHKEY env var; if omitted, loads from disk or prompts)
  -e, --ephemeral                    Make this node ephemeral (auto-cleanup on disconnect)
  -l, --exit-node-allow-lan-access   Allow access to local LAN while using exit node
  -t, --tcp stringArray              Forward a local TCP port to a remote host through the exit node, in the form 'LISTEN=TARGET' (e.g. '127.0.0.1:3900=test.com:3900'). Can be repeated to forward multiple ports.
  -n, --hostname string              Tailscale node name (hostname) (default "tailsocks")
      --local-dns                    Use local DNS resolver instead of resolving DNS through Tailscale
  -c, --login-server string          Optional control server URL (e.g. https://controlplane.tld for Headscale)
  -o, --oauth2                       Use OAuth2 credentials for authentication. When set, node is ephemeral by default.
  -a, --socks-addr string            SOCKS5 listen address. Set to an empty value to disable the SOCKS5 proxy. (default "127.0.0.1:5040")
  -p, --http-addr string             HTTP proxy listen address (e.g. '127.0.0.1:5041'). Disabled when empty.
  -s, --state-dir string             Directory to store tsnet state (default "./tsnet-state")
  -v, --version                      Show version
  -h, --help                         Show this help message
```

## Configuring Applications

### Web Browsers

**Firefox:**

1. Settings → Network Settings → Configure how Firefox connects to the internet
2. Select "Manual proxy configuration"
3. SOCKS Host: `127.0.0.1`, Port: `5040`
4. Select "SOCKS v5"

To use the HTTP proxy instead, fill in "HTTP Proxy" with `127.0.0.1` and port `5041`, then select "Also use this proxy for HTTPS".

**Chrome/Chromium:**

```sh
chrome --proxy-server="socks5://127.0.0.1:5040"

# Or, using the HTTP proxy
chrome --proxy-server="http://127.0.0.1:5041"
```

### Command-Line Tools

Many CLI tools support SOCKS5 proxies via environment variables:

```sh
# Will use your exit node's IP
curl https://api.ipify.org --proxy socks5://127.0.0.1:5040
```

Tools that only understand HTTP proxies can use the `http_proxy` and `https_proxy` environment variables, which many CLIs honor without any per-tool configuration:

```sh
export http_proxy=http://127.0.0.1:5041
export https_proxy=http://127.0.0.1:5041
export no_proxy=localhost,127.0.0.1
```

**Git:**

```sh
git config --global http.proxy socks5://127.0.0.1:5040

# Or, using the HTTP proxy
git config --global http.proxy http://127.0.0.1:5041
```

**SSH:**

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:5040 %h %p" user@host

# Or, using the HTTP proxy
ssh -o ProxyCommand="nc -X connect -x 127.0.0.1:5041 %h %p" user@host
```

## Examples

### Route Firefox through your home network

```sh
# Start TailSocks with your home exit node
tailsocks --exit-node home-server

# Configure Firefox to use SOCKS5 proxy at 127.0.0.1:5040
# Now browse with your home IP address
```

### Access internal development resources

```sh
# Start TailSocks (no exit node needed to access Tailnet)
tailsocks --exit-node office-node

# Use curl with the proxy
curl http://internal-service.tailnet --proxy socks5h://127.0.0.1:5040
```

### Run multiple instances for different exit nodes

```sh
# Terminal 1: Route through home
tailsocks --exit-node home --socks-addr 127.0.0.1:5040 --state-dir ./state-home

# Terminal 2: Route through office
tailsocks --exit-node office --socks-addr 127.0.0.1:5041 --state-dir ./state-office

# Now configure different apps to use different proxies
```

## Troubleshooting

**TailSocks won't start:**

- Ensure the exit node name or IP is correct
- Check that you have permission to use the exit node in your Tailscale settings
- Verify your Tailscale authentication is valid

**Traffic not routing through exit node:**

- Confirm your application is properly configured to use the SOCKS5 or HTTP proxy
- Check that the proxy address and port match TailSocks' listen address
- Verify the exit node is online and accessible
- Check Tailscale ACL to ensure that your node can use the exit node (destination name is `autogroup:internet`)

**Tailscale Magic DNS isn't working:**

- Ensure that you have configured your application to use the DNS resolver over the SOCKS5 proxy. For example, curl requires the use of `socks5h://` as protocol. This does not apply to the HTTP proxy, which always resolves names on the TailSocks side
- Ensure that Magic DNS is enabled in your Tailnet
- Ensure that Tailsocks is not running with the `--local-dns` flag

**Can't access LAN resources:**

- Use the `--exit-node-allow-lan-access` flag

## License

[MIT](./LICENSE.md)
