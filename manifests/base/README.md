# MTLS Server Kustomziation

The included files are the base resources necessary to run an MTLS server in kubernetes. There are a few items missing
that you will need to patch in yourself for this to actually work.

Create a kustomize folder for deployment and add the following configuration and customize for your needs.

`kustomization.yml`
```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: mtls
resources:
  - github.com/drGrove/mtls-server/kustomize?ref=<hash>
patches:
  - update-deployment-fqdn.patch.yaml
generatorOptions:
  disableNameSuffixHash: true
configMapGenerator:
  - name: mtls
    behavior: replace
    files:
      - files/config.ini
  - name: mtls-admin-seeds
    behavior: replace
    files:
        - files/admin_seeds/<your-pgp-key>.asc
  - name: mtls-user-seeds
    behavior: replace
    files:
        - files/user_seeds/<other-user-key>.asc
patchesJson6902:
  - target:
      group: networking.k8s.io
      version: v1beta1
      kind: Ingress
      name: mtls
    patch: |-
      - op: replace
        path: "/spec/tls/0/hosts/0"
        value: "certauth.<YOUR_DOMAIN>"
      - op: replace
        path: "/spec/rules/0/host"
        value: "certauth.<YOUR_DOMAIN>"
  - target:
      group: apps
      version: v1
      kind: Deployment
      name: mtls
    patch: |-
      - op: replace
        path: "/spec/template/spec/containers/0/env/0/value"
        value: "certauth.<YOUR_DOMAIN>"
```

`update-deployment-fqdn.patch.yaml`
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mtls
spec:
  template:
    spec:
      containers:
        - name: mtls
          env:
            - name: FQDN
              value: "certauth.<YOUR_DOMAIN>"
```

NOTE: If you decide to use something like [ksops][ksops] for your secret management or want to use a generator, you need
to make sure that your new secret has the following annotation:

```
…
metadata:
  annotations:
    kustomize.config.k8s.io/behavior: replace
```
