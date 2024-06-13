
# HelloID-Conn-Prov-Target-Ecare

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

> [!IMPORTANT]
> We are expecting in the near future an update of the Ecare API interface which will allow a cleaner method to correlate the user on the employee number.

<p align="center">
  <img src=".\assets\logo-ecare.svg">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Ecare](#helloid-conn-prov-target-Ecare)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Correlation configuration](#correlation-configuration)
      - [Field mapping](#field-mapping)
    - [Connection settings](#connection-settings)
    - [Prerequisites](#prerequisites)
    - [Remarks](#remarks)
  - [Setup the connector](#setup-the-connector)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Ecare_ is a _target_ connector. _Ecare_ provides a set of REST API's that allow you to programmatically interact with its data. The HelloID connector uses the API endpoints listed in the table below.

| Endpoint | Description |
| -------- | ----------- |
| <tokenurl>/connect/token   used for generating access token |
| <baseurl></scim/Users  |   used for all scim actions        |



The following lifecycle actions are available:

| Action                 | Description                                      |
| ---------------------- | ------------------------------------------------ |
| create.ps1             | PowerShell _create_ lifecycle action             |
| delete.ps1             | PowerShell _delete_ lifecycle action             |
| disable.ps1            | PowerShell _disable_ lifecycle action            |
| enable.ps1             | PowerShell _enable_ lifecycle action             |
| update.ps1             | PowerShell _update_ lifecycle action             |
| permissions/grantPermission.ps1    | PowerShell _grant_ lifecycle action. Grants a role to the user           |
| permissions/revokePermission.ps1   | PowerShell _revoke_ lifecycle action.  Revokes a role from the user      |
| permissions/permissions.ps1        | PowerShell _permissions_ lifecycle action. list the available roles       |
| resources/resources.ps1          | PowerShell _resources_ lifecycle action          |
| configuration.json     | Default _configuration.json_ |
| fieldMapping.json      | Default _fieldMapping.json_   |

## Getting started

### Provisioning PowerShell V2 connector

#### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.
See the description of each field in this file (or in the Helloid Fields tab after import).

#### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _Ecare_ to a person in _HelloID_.

To properly setup the correlation:
1. Make sure the Field mapping is configured first.

2. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                   | Value                             |
    | ------------------------- | --------------------------------- |
    | Enable correlation        | `True`                            |
    | Person correlation field  | ExternalId (field from Fields tab)
    | Account correlation field | employeeNumber (field from Fields tab)                                |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.



### Connection settings

The following settings are required to connect to the API.

| Setting  | Description                        | Mandatory |
| -------- | ---------------------------------- | --------- |
| ClientId | The ClientId to connect to the API | Yes       |
| ClientSecret | The ClientSecret to connect to the API | Yes       |
| TokenUrl | The URL to the identity provider that will generate the accesstoken for the Api connnection | Yes|
| BaseUrl  | The URL to SCIM service API root <https://<scim-service-url>>  | Yes       |


### Prerequisites

### Remarks


1) Make sure you set the number of concurrent actions (configuration tab) on 1. The external Api does at the moment not support simulaneous actions on the same user.

2) For some user properties as defined in the Field mapping, there is some additional mapping requried and perfomed in the powerschell scripts itself to create the actual Scim message.

3) At the moment the default correlation is done by means of the employeeNumber. The employeeNumber is also used as the Accountreference used by HelloId. Note that there is however at the moment not an explicit query available in the API on the employeeNumber. A query on the username is used instead and the API implicitly reconizes when the employeeNumber is specified in this query.

4) The API may return limited error information when an error occurs, often resulting in an error 400 or 500 without additional information. For instance  creating an account with an username which already is used, will result in an error 500.  A request lacking mandatory properties will result in an error 400.

5) The permission scripts are used to grant or revoke roles (i.e group memberships) to a user. Roles can only be revoked, when at least once a role has been granted by means of the API for the particular user.

6) The list of possible roles (groups) is returned by the permissions.ps1 script, and currently is a static list defined in the script. Unknown roles will be ignored by the API when granting/revoking roles.

7) Each of the fields Username, emailwork, and ExternalId are required to be unique


## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required. Like the _primary manager_ settings for a source connector.

## Getting help

The API uses the SCIM specification, see https://service-scim-o.ecare.nu/swagger  for the detailed specification of the supported calls.
Note that these listed may not be all implemented by your scim endpoint, but subset used by this connector should be.

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
