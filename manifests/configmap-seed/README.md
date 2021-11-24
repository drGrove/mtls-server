# Configmap based Seeding

### Configmap Generator based setup

This uses [kiwigrid/k8s-sidecar][kiwigrid-k8s-sidecar] to detect changes to configMaps based on labels.

```yaml
...
configMapGenerator:
- name: gpg-key-{username}
  options: { labels: { mtls_user_key: "1" } }
- name: gpg-key-{admin-username}
  options: { labels: { mtls_user_key: "1", mtls_admin_key: "1" } }
  files: [ path/to/key ]
```

On change: it updates the volume, and restarts mtls-server to update the trust store.

[kiwigrid-k8s-sidecar]: https://github.com/kiwigrid/k8s-sidecar
