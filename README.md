
# HelloID-Conn-Prov-Target-Ecare-PUUR

> [!WARNING]
> Team permissions in PUUR are assigned at contract level. When a new contract starts, PUUR removes the team permissions from the previous contract. HelloID does not grant them again because the person still meets the department- or function-based business rule conditions, so no new grant action is triggered. As a result, HelloID may show the entitlements as granted while the team permissions are missing from the active PUUR contract. Make sure the Teams permission update action is always executed to verify and restore these permissions. Configure _permissions/teams/grantPermission.ps1_ as the update action.

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible for acquiring connection details such as username, password, and certificates. A contract or agreement with the supplier may be required. Contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Ecare-PUUR/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Ecare-PUUR](#helloid-conn-prov-target-ecare-puur)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Team permissions and contract changes](#team-permissions-and-contract-changes)
    - [Roles](#roles)
    - [Unique fields and validation](#unique-fields-and-validation)
    - [Error handling](#error-handling)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Ecare-PUUR_ is a _target_ connector. _Ecare PUUR_ provides REST APIs that allow you to programmatically interact with its data.

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                                 | Remarks                                                          |
| ----------------------------------------- | --------- | --------------------------------------- | ---------------------------------------------------------------- |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable, Delete |                                                                  |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke                 | Roles are static; Teams are retrieved dynamically.               |
| **Resources**                             | ❌         | -                                       |                                                                  |
| **Entitlement Import: Accounts**          | ✅         | Import accounts                         |                                                                  |
| **Entitlement Import: Permissions**       | ✅         | Import roles and Teams                  |                                                                  |
| **Governance Reconciliation Resolutions** | ✅         | Disable, Delete, Revoke                 |                                                                  |

## Getting started

### HelloID Icon URL

URL of the icon used for the HelloID Provisioning target system:

```text
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Ecare-PUUR/refs/heads/main/Icon.png
```

### Requirements

- An employee account must exist in PUUR before HelloID can create a user account. Employee accounts are created by an external synchronization and are not managed by this connector.
- Set the number of concurrent actions to `1`. The API does not support simultaneous actions on the same user.

### Connection settings

The following settings are required to connect to the API.

| Setting        | Description                                                                      | Mandatory |
| -------------- | -------------------------------------------------------------------------------- | --------- |
| `ClientId`     | The client ID used to connect to the API.                                        | Yes       |
| `ClientSecret` | The client secret used to connect to the API.                                    | Yes       |
| `TokenUrl`     | The identity provider URL used to generate the access token.                     | Yes       |
| `BaseUrl`      | The root URL of the SCIM service, for example `https://service-scim-a.ecare.nu`. | Yes       |

### Correlation configuration

The correlation configuration specifies which properties are used to match an existing Ecare PUUR account to a person in HelloID.

| Setting                   | Value            |
| ------------------------- | ---------------- |
| Enable correlation        | `True`           |
| Person correlation field  | `ExternalId`     |
| Account correlation field | `employeeNumber` |

> [!TIP]
> For more information on correlation, refer to the HelloID [correlation documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html).

### Field mapping

Import the field mapping using the _fieldMapping.json_ file. Some user properties are additionally mapped by the PowerShell scripts when creating the SCIM request.

### Account Reference

The account reference is populated from the `id` property returned by Ecare PUUR when an account is retrieved or created.

## Remarks

### Team permissions and contract changes

PUUR assigns team permissions at contract level. When a contract changes or is renewed, permissions may expire even though HelloID still considers them assigned. Configure _permissions/teams/grantPermission.ps1_ as both the grant and update action for Teams permissions so the membership is verified and restored on the active contract.

### Roles

The available roles are defined statically in _permissions/roles/permissions.ps1_. Roles not present in this list are ignored. A role can only be revoked after it has been granted through the API at least once for that user. Roles that do not exist are ignored by the API.

### Unique fields and validation

`userName`, `WorkEmail`, `employeeNumber`, and `ExternalId` must be unique. Email addresses and usernames may also have undocumented requirements; invalid values have resulted in a `500 Internal Server Error` during testing.

### Error handling

The API provides limited error details and may return a `400` or `500` response without a useful explanation. For example, a duplicate username can result in a `500`, while a request missing mandatory properties can result in a `400`. The `Resolve-EcareError` function reports the available response details.

## Development resources

### API endpoints

The connector uses the following endpoints:

| Endpoint            | HTTP methods       | Description                                                                      |
| ------------------- | ------------------ | -------------------------------------------------------------------------------- |
| `/connect/token`    | POST               | Generate an OAuth access token.                                                  |
| `/scim/Users`       | GET, POST          | Retrieve and create user accounts.                                               |
| `/scim/Users/{id}`  | GET, PATCH, DELETE | Retrieve, update, enable, disable, delete accounts, and update role memberships. |
| `/scim/Groups`      | GET                | Retrieve Teams for permissions and permission import.                            |
| `/scim/Groups/{id}` | PATCH              | Grant or revoke a Team membership.                                               |

### API documentation

The Ecare PUUR SCIM API specification is available at [service-scim-o.ecare.nu/swagger](https://service-scim-o.ecare.nu/swagger). Not all endpoints in the specification may be implemented by the service.

## Getting help

> [!TIP]
> For more information on configuring a HelloID PowerShell connector, refer to the [HelloID PowerShell V2 target system documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html).

## HelloID docs

The official HelloID documentation can be found at [docs.helloid.com](https://docs.helloid.com/).
