# The WAF plugin is prebuilt upstream; no compilers, curl|sh, or apt repositories
# are required in the final image. Bump only after CI and load tests pass.
FROM ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0@sha256:d66f944831428ea27039207fa4019bea55f9ea0a876d7b0dc8cc7c9e385fa4b1 AS waf

FROM envoyproxy/envoy:v1.40.2@sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb

LABEL org.opencontainers.image.title="EnvoyOnSteroid" \
      org.opencontainers.image.description="Envoy v3 API with a Coraza/OWASP CRS WAF filter" \
      org.opencontainers.image.source="https://github.com/redoracle/EnvoyOnSteroid" \
      org.opencontainers.image.licenses="MIT"

COPY --from=waf --chmod=0555 /plugin.wasm /etc/envoy/coraza.wasm
COPY --chmod=0444 envoy.yaml /etc/envoy/envoy.yaml

# The upstream Envoy image uses uid/gid 101 for its unprivileged envoy user.
USER 101:101
EXPOSE 8080
STOPSIGNAL SIGTERM
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
