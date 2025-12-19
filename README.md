# TailSocks

Route traffic through any Tailscale exit node using a local SOCKS5 proxy.

## What is TailSocks?

TailSocks creates a local SOCKS5 proxy server that automatically routes all traffic through a Tailscale exit node of your choice. This gives you the flexibility to:

- **Route specific applications** through your Tailscale network without affecting your entire system
- **Use different exit nodes** for different applications simultaneously
- **Access your tailnet resources** from applications that support SOCKS5 proxies
- **Bypass VPN limitations** in applications that don't support traditional VPNs

## Use Cases

- **Selective routing**: Route only specific applications (browsers, CLI tools, etc) through your Tailscale network
- **Testing**: Test how your services behave from different network locations
- **Development**: Access development resources on your tailnet without configuring your entire system
- **Privacy**: Route sensitive traffic through your home or office network
- **Multiple exit nodes**: Run multiple instances with different exit nodes for different purposes

## Installation

```sh
go install github.com/italypaleale/tailsocks@latest
```

Or build from source:

```sh
git clone https://github.com/italypaleale/tailsocks
cd tailsocks
go build
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

If there's no existing authenticatio state, you will see a URL to authenticate your node in the logs.

### Custom Tailscale Control Server

If you're using Headscale or another custom control server:

```sh
tailsocks --exit-node home-server --login-server https://headscale.example.com
```

## Command-Line Options

```text
  -a, --socks-addr string                SOCKS5 listen address (default "127.0.0.1:5040")
  -s, --state-dir string                 Directory to store tsnet state (default "./tsnet-state")
  -n, --hostname string                  Tailscale node name (default "tailsocks")
  -k, --authkey string                   Tailscale auth key (or set TS_AUTHKEY env var)
  -x, --exit-node string                 Exit node: IP or MagicDNS name (required)
  -l, --exit-node-allow-lan-access       Allow LAN access while using exit node
  -c, --login-server string              Custom control server URL (e.g., Headscale)
  -h, --help                             Show help message
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
# Start TailSocks (no exit node needed to access tailnet)
tailsocks --exit-node office-node

# Use curl with the proxy
curl http://internal-service.tailnet --proxy socks5://127.0.0.1:5040
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

**Can't access LAN resources:**

- Use the `--exit-node-allow-lan-access` flag

## License

[MIT](./LICENSE.md)
