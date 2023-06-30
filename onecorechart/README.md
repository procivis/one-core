[![Quality Gate Status](https://sonarqube.dev.one-trust-solution.com/api/project_badges/measure?project=procivis_one_one-core_AYkHTYbt1WzC4GkDJJ75&metric=alert_status&token=sqb_d3d9dfb52da864937b6d90e597437bd70a1eba30)](https://sonarqube.dev.one-trust-solution.com/dashboard?id=procivis_one_one-core_AYkHTYbt1WzC4GkDJJ75)

# Deploying the One CORE

Fetch dependencies 
```shell
helm dep build
```

#### Update the deployment:

* Dev (Namespace: default) [https://core.dev.one-trust-solution.com](https://core.dev.one-trust-solution.com)
```shell
helm upgrade --install one-core . --values values/desk.dev.one-trust-solution.yaml --namespace default
```

* Test (Namespace: one-test) [https://core.test.one-trust-solution.com](https://core.test.one-trust-solution.com)
```shell
helm upgrade --install one-core . --values values/desk.test.one-trust-solution.yaml --namespace one-test
```

* Uninstall chart:
```shell
helm uninstall one-core --namespace <NAMESPACE>
```
