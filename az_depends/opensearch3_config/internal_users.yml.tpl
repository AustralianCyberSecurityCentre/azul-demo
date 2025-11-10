---
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: "internalusers"
  config_version: 2

# Define your internal users here

## Demo users

admin:
  hash: "ADMIN_PLACEHOLDER"
  reserved: true
  backend_roles:
  - "admin"
  description: "admin user"

kibanaserver:
  hash: "KS_PLACEHOLDER"
  reserved: true
  description: "kibanaserver user"

opensearch_dashboards_system:
  hash: "KS_PLACEHOLDER"
  reserved: true
  description: "kibanaserver user"

azul_writer:
  hash: "AZW_PLACEHOLDER"
  reserved: true
  description: "azul_writer user"
