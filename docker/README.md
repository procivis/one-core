# MariaDB management

---

## Backup & Restore

### Dump data

- MySQL local credentials

```shell
export MYSQL_USER=core
export MYSQL_PASSWORD=886eOqVMmlHsayu6Vyxw
export MYSQL_DATABASE=core
export BACKUP_PATH="dumps/db-dump-$(date +"%d-%m-%Y").sql"
```

- Dump all tables in `core` db

```shell
docker compose -f db.yml exec mariadb mysqldump -u ${MYSQL_USER} -p${MYSQL_PASSWORD} --hex-blob ${MYSQL_DATABASE} > ${BACKUP_PATH}
```

- Dump only key table in `core` db

```shell
docker compose -f db.yml exec mariadb mysqldump -u ${MYSQL_USER} -p${MYSQL_PASSWORD} --hex-blob ${MYSQL_DATABASE} key > ${BACKUP_PATH}
```

### Restore data

```shell
docker compose -f db.yml exec -T mariadb mysql -u ${MYSQL_USER} -p${MYSQL_PASSWORD} ${MYSQL_DATABASE} < ${BACKUP_PATH}
```

or

```shell
cat ${BACKUP_PATH} | docker compose -f db.yml exec -T mariadb mysql -u ${MYSQL_USER} -p${MYSQL_PASSWORD} ${MYSQL_DATABASE}
```

---

## Azure key template

- Replace `organizationID` with `UUID of Organization` in sql file

```shell
AZURE_SQL_TEMPLATE_PATH="azure_key_tpl.sql"
ORGANIZATION_ID="2476ebaa-0108-413d-aa72-c2a6babd423f"
RESULT_FILE="azure_key_${ORGANIZATION_ID}.sql"
sed "s|organizationID|${ORGANIZATION_ID}|g" ${AZURE_SQL_TEMPLATE_PATH} > ${RESULT_FILE}
```

- Restore Azure key in kubernetes cluster (pod)

```shell
kubectl exec -it one-core-mariadb-0 -n <namespace> -- mysql -u <dbUser> -p<password> <dbName> < ${RESULT_FILE}
```
