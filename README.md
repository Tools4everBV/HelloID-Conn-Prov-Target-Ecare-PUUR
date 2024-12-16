
# HelloID-Conn-Prov-Target-Ecare-PUUR

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Ecare-PUUR](#helloid-conn-prov-target-ecare-puur)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Field mapping](#field-mapping)
      - [Correlation configuration](#correlation-configuration)
    - [Connection settings](#connection-settings)
    - [Remarks](#remarks)
      - [Employee account required](#employee-account-required)
      - [Concurrent actions](#concurrent-actions)
      - [Additional mapping](#additional-mapping)
      - [Correlation by `externalId`](#correlation-by-externalid)
      - [Limited error handling](#limited-error-handling)
        - [Error handling function](#error-handling-function)
      - [Roles can only be revoked](#roles-can-only-be-revoked)
      - [Static permissions](#static-permissions)
      - [Email address and userName have some requirements that are unknown.](#email-address-and-username-have-some-requirements-that-are-unknown)
      - [Unique fields](#unique-fields)
      - [`employeeNumber` and `id` can be the same.](#employeenumber-and-id-can-be-the-same)
  - [Setup the connector](#setup-the-connector)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Ecare-PUUR_ is a _target_ connector. _Ecare PUUR_ provides a set of REST API's that allow you to programmatically interact with its data. The HelloID connector uses the API endpoints listed in the table below.

| Endpoint       | Description                      |
| -------------- | -------------------------------- |
| /connect/token | Used for generating access token |
| /scim/v2/Users | Used for all SCIM operations     |

The API specification can be found on: https://service-scim-o.ecare.nu/swagger

> [!NOTE]
> Note that the endpoints listed in the specification may not be all implemented. The required endpoints for the connector however should be available.

The following lifecycle actions are available:

| Action                           | Description                                                         |
| -------------------------------- | ------------------------------------------------------------------- |
| create.ps1                       | PowerShell _create_ lifecycle action                                |
| delete.ps1                       | PowerShell _delete_ lifecycle action                                |
| disable.ps1                      | PowerShell _disable_ lifecycle action                               |
| enable.ps1                       | PowerShell _enable_ lifecycle action                                |
| update.ps1                       | PowerShell _update_ lifecycle action                                |
| permissions/grantPermission.ps1  | PowerShell _grant_ lifecycle action. Grants a role to the user      |
| permissions/revokePermission.ps1 | PowerShell _revoke_ lifecycle action.  Revokes a role from the user |
| permissions/permissions.ps1      | PowerShell _permissions_ lifecycle action. list the available roles |
| configuration.json               | Default _configuration.json_                                        |
| fieldMapping.json                | Default _fieldMapping.json_                                         |

## Getting started

### Provisioning PowerShell V2 connector

#### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.
See the description of each field in this file (or in the HelloID Fields tab after import).

#### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _Ecare PUUR_ to a person in _HelloID_.

To properly setup the correlation:
1. Make sure the Field mapping is configured first.

2. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                   | Value                                  |
    | ------------------------- | -------------------------------------- |
    | Enable correlation        | `True`                                 |
    | Person correlation field  | ExternalId (field from Fields tab)     |
    | Account correlation field | employeeNumber (field from Fields tab) |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                                                                                 | Mandatory |
| ------------ | ------------------------------------------------------------------------------------------- | --------- |
| ClientId     | The ClientId to connect to the API                                                          | Yes       |
| ClientSecret | The ClientSecret to connect to the API                                                      | Yes       |
| TokenUrl     | The URL to the identity provider that will generate the access token for the API connection | Yes       |
| BaseUrl      | The URL to SCIM service API root <https://<scim-service-url>>                               | Yes

### Remarks

#### Employee account required

Note that an employee account is required before a user account can be created. If the employee doesn't exist, a __500 internal server error__ will be returned. The employee account is not managed by _HelloID_. Employee accounts are created by an external synchronization.

#### Concurrent actions

Make sure you set the number of concurrent actions (configuration tab) on 1. The external Api does at the moment not support simultaneous actions on the same user.

#### Additional mapping

For some user properties as defined in the Field mapping, there is some additional mapping required and performed in the PowerShell scripts itself to create the actual the SCIM message.

#### Correlation by `externalId`

At the moment, correlation is done by means of the `externalId`. The `id` that will be returned if an account is retrieved or created will be used as the account reference by HelloId.

#### Limited error handling

The API returns limited error information when an error occurs, often resulting in an error 400 or 500 without additional information. For instance; creating an account with a username which already is used, will result in an error 500. A request lacking mandatory properties will result in an error 400.

##### Error handling function

Because error handling is limited within the API, the `Resolve-EcareError` function is still our basic / un-modified implementation.

#### Roles can only be revoked

The permission scripts are used to grant or revoke roles (i.e group memberships) to a user. Roles can only be revoked, when at least once a role has been granted by means of the API for the particular user.

> [!NOTE]
> Roles that do not exist are ignored.

#### Static permissions

The list of possible roles (groups) is provided by the _permissions.ps1_ script, which currently contains a statically defined list within the script. Any roles not recognized by this list will be ignored by the API when attempting to grant or revoke roles.

#### Email address and userName have some requirements that are unknown.

During testing, we encountered situations where the email address and username provided during the account creation process were not accepted, resulting in a '500 Internal Server Error'. This suggests there may be hidden requirements or constraints that we are unaware of.

#### Unique fields

The fields: `userName`, `WorkEmail`, `employeeNumber` and `ExternalId` are required to be unique.

## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required. Like the _primary manager_ settings for a source connector.

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/5120-helloid-conn-prov-target-ecare)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
