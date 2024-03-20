[![Quality Gate Status](https://sonarqube.dev.one-trust-solution.com/api/project_badges/measure?project=procivis_one_one-core_AYkHTYbt1WzC4GkDJJ75&metric=alert_status&token=sqb_d3d9dfb52da864937b6d90e597437bd70a1eba30)](https://sonarqube.dev.one-trust-solution.com/dashboard?id=procivis_one_one-core_AYkHTYbt1WzC4GkDJJ75)

# Deploying the One CORE

## Sops secrets integration:

**Requirements:**
* Sops - [https://github.com/mozilla/sops/releases](https://github.com/mozilla/sops/releases)
* Helm secrets - [https://github.com/jkroepke/helm-secrets](https://github.com/jkroepke/helm-secrets)

**Azure Key Vault or GPG required:**
* GPG - [https://gnupg.org/](https://gnupg.org/)
* KeyVault - [https://portal.azure.com/](https://portal.azure.com/#@procivis.ch/resource/subscriptions/a2ed3781-b096-47a1-a919-e2b381df98d4/resourceGroups/global-resources/providers/Microsoft.KeyVault/vaults/one-global/overview)


> **_NOTE:_**  Download private key from Bitwarden (**ONE Secrets PGP Key**)


* Import key to gpg
```shell
gpg --import dev.procivis.sec
```

* Verify import
```shell
gpg -k
gpg -K
gpg --list-secret-keys
```

In the file [.sops.yaml](.sops.yaml) we have use `pgp fingerprint` of the key and Azure KeyVault key identifier

#### File encryption

* Using Raw secret file:
```shell
sops -e values/dev/raw_secrets.yaml > values/dev/secrets.yaml
```

* Create or Edit secret file on a fly (vim editor will be opened):
```shell
sops values/dev/secrets.yaml
```

#### File decryption

* To Raw file:
```shell
sops -d values/dev/secrets.yaml > values/dev/raw_secrets.yaml
```

---

## Helm integration

Fetch dependencies 
```shell
helm dep build
```

#### Update the deployment:

* Dev (Namespace: default) [https://core.dev.procivis-one.com](https://core.dev.procivis-one.com/swagger-ui/)
```shell
helm upgrade --install one-core . --values values/dev/main.yaml -f secrets://values/dev/secrets.yaml --namespace default
```

* Test (Namespace: one-test) [https://core.test.procivis-one.com](https://core.test.procivis-one.com/swagger-ui/)
```shell
helm upgrade --install one-core . --values values/test/main.yaml -f secrets://values/test/secrets.yaml --namespace one-test
```

* Demo (Namespace: default) [https://core.demo.procivis-one.com](https://core.demo.procivis-one.com/swagger-ui/)
```shell
helm upgrade --install one-core . --values values/demo/main.yaml -f secrets://values/demo/secrets.yaml --namespace default
```

* Trial (Namespace: trial) [https://core.trial.procivis-one.com](https://core.demo.procivis-one.com/swagger-ui/)
```shell
helm upgrade --install one-core . --values values/trial/main.yaml -f secrets://values/trial/secrets.yaml --namespace trial
```

* Uninstall chart:
```shell
helm uninstall one-core --namespace <namespace>
```

---

## Debugging

* Helm template
```shell
helm template . --values values/dev/main.yaml -f secrets://values/dev/secrets.yaml
```

* Debug deploy image
```shell
export IMAGE="registry.gitlab.procivis.ch/procivis/one/one-operations/az-helm-kubectl:1.27.7"
docker run --rm -it -v "./onecorechart/:/chart/" $IMAGE
```
