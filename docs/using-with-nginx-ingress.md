# Using `mtls-server` with Nginx Ingress

Using Mutual TLS in Ingress Ngninx along with the `mtls-server` gives you the ability to quickly and securely create
client certificates and the changes to your kubernetes ingresses are very minimal.

```yaml
# ingress.yaml
…
metadata:
  …
  annotations:
    nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
    nginx.ingress.kubernetes.io/auth-tls-secret: "mtls/mtls-certs"
    nginx.ingress.kubernetes.io/auth-tls-verify-depth: "1"
```
