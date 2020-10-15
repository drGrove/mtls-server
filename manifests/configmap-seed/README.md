# Configmap based Seeding

### Configmap Generator based setup

This uses [kiwigrid/k8s-sidecar][kiwigrid-k8s-sidecar], currently
[patched](https://github.com/kiwigrid/k8s-sidecar/pull/96) using a custom version to support keys exported as binary or
ascii armour.

```yaml
...
configMapGenerator:
- name: gpg-key-{username}
  options: { labels: { mtls_user_key: "1" } }
- name: gpg-key-{admin-username}
  options: { labels: { mtls_user_key: "1", mtls_admin_key: "1" } }
  files: [ path/to/key ]
```

[kiwigrid-k8s-sidecar]: https://github.com/kiwigrid/k8s-sidecar
