# MTLS Server Kustomziation

The included files are the base resources necessary to run an MTLS server in kubernetes. There are a few items missing
that you will need to patch in yourself for this to actually work.

Create a kustome folder for deployment and add the following configuration and customize for your needs.

`kustomization.yml`
```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: mtls
resources:
  - github.com/drGrove/mtls-server/kustomize?ref=<hash>
patches:
  - ingress.patch.yml
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
  - op: replace
    path: "/spec/tls/0/host"
    value: "certauth.<YOUR DOMAIN>"
  - op: replace
    path: "/spec/rules/0/host"
    value: "certauth.<YOUR DOMAIN>"
  - op: replace
    path: "/spec/template/spec/contianers/0/env/0/value"
    value: "certauth.<YOUR DOMAIN>"
```
