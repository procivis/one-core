# Deploying the One Desk

Fetch dependencies 
```shell
helm dep build
```


Update the deployment:
* Dev  [https://core.dev.one-trust-solution.com](https://core.dev.one-trust-solution.com)

```shell
helm upgrade --install one-core . --values values/desk.dev.one-trust-solution.yaml --namespace default
```

Uninstall chart:

```shell
helm uninstall one-core --namespace default
```
