# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.0.1]

### Changed

- Clarified the contract-level behavior of PUUR team permissions and the required Teams permission update action.
- Added import scripts
- Team display names are now fully URL-encoded when granting and revoking team permissions, so names with special characters work ([#3](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Ecare-PUUR/issues/3)). The name is no longer trimmed, because team names in eCare can end with a space
- Account import now returns `Data` with the field names of the fieldMapping (e.g. `employeeNumber` from the enterprise extension), which fixes the 'Correlation field is missing' error
- Fixed paging in the teams permission import, which only imported the first page of teams
- Role permission import now uses the same `Reference` as `permissions.ps1`, so imported roles match the existing permissions
- Role permission import now reads the roles of all accounts in one pass, because eCare ignores the SCIM `roles` filter and returned all users for every role
- Added the roles `Client aanmaken` and `Zorgcentrale`
- Team permission import now reads the `members` of each team and translates them (on `id`, `employeeNumber`, `externalId` or `userName`) to the account reference, because eCare ignores the SCIM `groups` filter and returned all users for every team
- Role and team permission imports return the account references in batches of 500, the same as the other Tools4ever connectors
- Update, enable and disable now compare the mapped data with the account converted to the field names of the fieldMapping, so unchanged accounts are no longer patched on every action
- `WorkEmail` is now patched as a SCIM `emails` array (the same as on create), `employeeNumber` with the enterprise extension path and `active` as a boolean
- Enable and disable always set `active`, also when other properties are updated in the same action
- Create, update, enable and disable store the account data with the field names of the fieldMapping instead of the raw SCIM object
- All lifecycle and permission scripts now return a result and audit log in preview (dry run)
- Teams permissions: the member `from` date is sent in ISO 8601 format (also on Windows PowerShell 5.1) and the unsupported `name` property is removed
- Removed debug output from the disable script
- Create: the correlation filter uses the configured account correlation field, a URL-encoded value, and verifies that the found account has the correlation value
- Create: when eCare returns an error (or no account) while the account is created, the account is looked up again and correlated, so a retry is no longer needed
- Create: clear error messages when eCare returns a 404 or 500 because the employee does not exist, and the account reference is kept when the disable request returns no account
- Removed the duplicate log line in the grant and revoke scripts
- Grant and revoke scripts log the permission name from `PermissionDisplayName` (`References.Permission.DisplayName` is empty)
- All API calls use `Invoke-EcareRestMethod`
- README: `permissions/teams/grantPermission.ps1` is used as the update script for Teams permissions

## [1.0.0] - 30-05-2024

This is the first official release of _HelloID-Conn-Prov-Target-Ecare_. This release is based on template version _1.2.0_.

### Added

### Changed

### Deprecated

### Removed