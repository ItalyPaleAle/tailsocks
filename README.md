# TailSocks

Route traffic through any Tailscale exit node using a local SOCKS5 proxy.

## What is TailSocks?

TailSocks creates a local SOCKS5 proxy server that automatically routes all traffic through a Tailscale exit node of your choice. This gives you the flexibility to:

- **Route specific applications** through your Tailscale network without affecting your entire system
- **Use different exit nodes** for different applications simultaneously
- **Access your Tailnet resources** from applications that support SOCKS5 proxies
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
  ghcr.io/italypaleale/tailsocks:1
```

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
  -n, --hostname string              Tailscale node name (hostname) (default "tailsocks")
      --local-dns                    Use local DNS resolver instead of resolving DNS through Tailscale
  -c, --login-server string          Optional control server URL (e.g. https://controlplane.tld for Headscale)
  -o, --oauth2                       Use OAuth2 credentials for authentication. When set, node is ephemeral by default.
  -a, --socks-addr string            SOCKS5 listen address (default "127.0.0.1:5040")
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

**Chrome/Chromium:**

```sh
chrome --proxy-server="socks5://127.0.0.1:5040"
```

### Command-Line Tools

Many CLI tools support SOCKS5 proxies via environment variables:

```sh
# Will use your exit node's IP
curl https://api.ipify.org --proxy socks5://127.0.0.1:5040
```

**Git:**

```sh
git config --global http.proxy socks5://127.0.0.1:5040
```

**SSH:**

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:5040 %h %p" user@host
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

- Confirm your application is properly configured to use the SOCKS5 proxy
- Check that the SOCKS5 address and port match TailSocks' listen address
- Verify the exit node is online and accessible
- Check Tailscale ACL to ensure that your node can use the exit node (destination name is `autogroup:internet`)

**Tailscale Magic DNS isn't working:**

- Ensure that you have configured your application to use the DNS resolver over the SOCKS5 proxy. For example, curl requires the use of `socks5h://` as protocol
- Ensure that Magic DNS is enabled in your Tailnet
- Ensure that Tailsocks is not running with the `--local-dns` flag

**Can't access LAN resources:**

- Use the `--exit-node-allow-lan-access` flag

## License

[MIT](./LICENSE.md)
