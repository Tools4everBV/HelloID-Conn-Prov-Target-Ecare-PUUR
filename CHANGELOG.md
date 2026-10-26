# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.0.1]

### Changed

- Clarified the contract-level behavior of PUUR team permissions and the required Teams permission update action.
- Added import scripts
- Team display names are now fully URL-encoded when granting and revoking team permissions, so names with special characters work ([#3](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Ecare-PUUR/issues/3))
- Account import now returns `Data` with the field names of the fieldMapping (e.g. `employeeNumber` from the enterprise extension), which fixes the 'Correlation field is missing' error
- Fixed paging in the teams permission import, which only imported the first page of teams
- Role permission import now uses the same `Reference` as `permissions.ps1`, so imported roles match the existing permissions
- Role permission import now reads the roles of all accounts in one pass, because eCare ignores the SCIM `roles` filter and returned all users for every role
- Added the roles `Client aanmaken` and `Zorgcentrale`
- Team permission import now reads the `members` of each team and translates them (on `id`, `employeeNumber`, `externalId` or `userName`) to the account reference, because eCare ignores the SCIM `groups` filter and returned all users for every team
- Role and team permission imports return the account references in batches of 500, the same as the other Tools4ever connectors

## [1.0.0] - 30-05-2024

This is the first official release of _HelloID-Conn-Prov-Target-Ecare_. This release is based on template version _1.2.0_.

### Added

### Changed

### Deprecated

### Removed