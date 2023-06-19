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
