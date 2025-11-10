# Azul Demo

## Introduction

Project for setting up an extremely basic Azul 3 deployment for development and testing.

## Getting Started

The deployment is split into separate compose projects:

* az_depends: All non-Azul services that are dependencies. Required for pretty
  much all dev/testing.

  * keycloak for OIDC
  * minio
  * opensearch
  * opensearch-dashboard
  * kafka

* az_core: Azul.

  * dispatcher
  * docs
  * ingesters
  * restapi
  * webui

* az_plugins: Running plugins.

  * 3 plugins

> **WARNING**
>
> If you are going to run OpenSearch, please ensure you have expanded the max
> ulimits as per OpenSearch's/Elasticsarch's documentation. If you do not do
> this stability problems are likely to occur.
>
> See: https://www.elastic.co/guide/en/elasticsearch/reference/current/setting-system-settings.html

## Basic localhost dev/testing

The default Docker Compose files in each project directory can be run without
additional input to start up a local instance (ie: `docker compose up -d`). The
only thing to watch out for is to start them up in the correct order, and wait
for them to initialise (ie ALL `depends` services must be in the `healthy` state
before starting `core`).

Please wait 2 minutes after starting `az_depends` then proceed to start `az_core`.

They must be started in:

  1. az_depends
  2. az_core
  3. az_plugins

If you don't want to leave the top level directory you can start them using:

```bash
# run dependencies
docker compose -f az_depends/docker-compose.yml up -d

# wait 3-5 minutues till you see the following string from the Opensearch container, then contunue to the next step
*************************** Opensearch inatialized ***************************

# run Azul
docker compose -f az_core/docker-compose.yml up -d

# plugins
docker compose -f az_plugins/docker-compose.yml up -d
```

Note: If you get 403 errors on the WebUI, please ensure the  `Opensearch inatialized` shows before starting up `az_core` as mentioned above.

> **INFO**
>
> This setup can also be used on a remote development machine. You just need to
> be sure to port forward the relevant service ports:
>
>  * 8123 (web ui)
>  * 80   (traefik for OIDC auth)
>

Once running, Azul will be available at: http://localhost:8123/

You can sign in as the `basic` user with password `basic12345`.

## Customising the deployment

Configuration can be modifed before starting the containers. The most important
ones are:

* New users and additional permissions can be added via the
  `az_depends/oidc_config/users.json` file.
* Additional oidc clients (eg for azul client) can be added via the
  `az_depends/oidc_config/clients.json` file.
* Your own OpenSearch certificates can be added in the directory:
  `az_depends/opensearch_config/certs`
  * new testing certificates can be generated using the script:
  `az_depends/opensearch_config/gen-certs/gen-certs.sh`
