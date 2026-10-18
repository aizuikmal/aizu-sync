# Caddy with a DNS provider module, for DNS-01 certificates on a private network.
# Swap the module for your provider: https://caddyserver.com/docs/modules/ (dns.providers.*)
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2
COPY --from=build /usr/bin/caddy /usr/bin/caddy
