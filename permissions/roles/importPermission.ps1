#################################################
# HelloID-Conn-Prov-Target-Ecare-importPermission-Roles
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Get-GenericScimOAuthToken {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $true)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]
        $TokenUrl
    )
    try {

        $headers = @{
            'content-type' = 'application/x-www-form-urlencoded'
        }

        $body = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            grant_type    = 'client_credentials'
            scope         = "Ecare.Service.SCIM"
        }

        $splatParams = @{
            Uri     = "$($TokenUrl)/connect/token"
            Method  = 'POST'
            Headers = $headers
            Body    = $body
        }

        $Response = Invoke-RestMethod @splatParams
        Write-Output $Response.access_token

    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}
function Invoke-EcareRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]
        $Headers = @{}
    )

    process {
        try {
            $splatParams = @{
                Uri         = $Uri
                Headers     = $headers
                Method      = $Method
                ContentType = $ContentType
            }

            if ($Body) {
                $splatParams['Body'] = $Body
            }
            Invoke-RestMethod @splatParams -Verbose:$false
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
function Resolve-EcareError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            # $httpErrorObj.FriendlyMessage = $errorDetailsObject.message
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails # Temporarily assignment
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
#endregion
try {
    Write-Information 'Starting eCare PUUR permission roles entitlement import'

    # Set authentication headers
    $accessToken = Get-GenericScimOAuthToken -ClientID $actionContext.Configuration.ClientId -ClientSecret $actionContext.Configuration.ClientSecret -TokenUrl $actionContext.Configuration.tokenUrl
    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $staticRoles = @(
        'Accountbeheer',
        'Administratie-client',
        'Administratie-medewerker',
        'Client aanmaken',
        'Clientadministratie Wachtlijst',
        'Clientadministratie Wachtlijstbeheer',
        'Clienten',
        'Coach',
        'Coordinator',
        'Declareren',
        'Documentbeheer',
        'Gedragsdeskundige',
        'Inzage Clientgegevens',
        'Medewerker',
        'Pleinauteur',
        'Roosteraar',
        'Serviceteam Applicatiebeheer',
        'Serviceteam Hrm Mutaties',
        'Serviceteam Medewerker',
        'Serviceteam Salarisverwerking',
        'Superuser',
        'Wachtlijstrapportages',
        'Zorgcentrale',
        'Zorgmessenger Regisseur',
        'Zorgmessenger Serviceteam'
    )

    # The SCIM filter on roles is not supported by eCare (it returns all users), so retrieve all users once and read the roles of each user
    Write-Information 'Starting getting the roles of each account'
    $roleMembers = @{}
    $take = 100
    $skip = 1 # SCIM uses 1-based index
    $moreRecords = $true

    while ($moreRecords) {
        $splatGetAccounts = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users?startIndex=$skip&count=$take"
            Method  = 'GET'
            Headers = $headers
        }

        $GetResponse = Invoke-EcareRestMethod @splatGetAccounts

        foreach ($user in $GetResponse.Resources) {
            foreach ($userRole in @($user.roles)) {
                # Roles can be returned as a string or as a SCIM multi-valued object
                if ($userRole -is [string]) {
                    $roleName = $userRole
                }
                elseif (-not [string]::IsNullOrEmpty($userRole.value)) {
                    $roleName = $userRole.value
                }
                else {
                    $roleName = $userRole.display
                }
                if ([string]::IsNullOrEmpty($roleName)) {
                    continue
                }

                $roleKey = $roleName.Trim().ToLower()
                if (-not $roleMembers.ContainsKey($roleKey)) {
                    $roleMembers[$roleKey] = [System.Collections.Generic.List[string]]::new()
                }
                $roleMembers[$roleKey].Add($user.id)
            }
        }

        # Stop when the last page is reached, totalResults is not reliable so check the number of returned resources
        if (@($GetResponse.Resources).Count -lt $take) {
            $moreRecords = $false
        }
        else {
            $skip += $take
        }
    }

    if ($roleMembers.Count -eq 0) {
        Write-Warning 'No roles found on any of the accounts. Verify that eCare returns the roles attribute when listing users'
    }

    # Output permission entitlements with account references in batches to prevent exceeding maximum limits
    $importedPermissionEntitlements = 0
    $batchSize = 500
    foreach ($role in $staticRoles) {
        # The permission reference is the lowercase role name, the same as in permissions.ps1
        $roleReference = $role.ToLower()
        $groupMembers = @($roleMembers[$roleReference] | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)

        $permission = @{
            PermissionReference = @{
                Reference = $roleReference
            }
            Description         = "Rol - $role"
            DisplayName         = $role
            AccountReferences   = $null
        }
        for ($i = 0; $i -lt $groupMembers.Count; $i += $batchSize) {
            # Use a copy of the permission for each batch, so earlier batches are not overwritten
            $permissionBatch = $permission.Clone()
            $permissionBatch.AccountReferences = @($groupMembers[$i..([Math]::Min($i + $batchSize - 1, $groupMembers.Count - 1))])
            Write-Output $permissionBatch
            $importedPermissionEntitlements += $permissionBatch.AccountReferences.Count
        }
    }

    $unknownRoles = @($roleMembers.Keys | Where-Object { $_ -notin @($staticRoles | ForEach-Object { $_.ToLower() }) })
    if ($unknownRoles.Count -gt 0) {
        Write-Warning "Roles found on accounts that are not in the list of roles and are not imported: [$($unknownRoles -join ', ')]"
    }

    Write-Information "eCare PUUR permission roles entitlement import completed. Roles: [$($staticRoles.Count)]. Result count: [$importedPermissionEntitlements]"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-EcareError -ErrorObject $ex
        Write-Error "Could not import eCare PUUR permission roles entitlements. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Error "Could not import eCare PUUR permission roles entitlements. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}
