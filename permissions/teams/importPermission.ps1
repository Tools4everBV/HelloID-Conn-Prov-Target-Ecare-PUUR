#################################################
# HelloID-Conn-Prov-Target-Ecare-importPermission-Teams
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
    Write-Information 'Starting eCare PUUR permission teams entitlement import'

    # Set authentication headers
    $accessToken = Get-GenericScimOAuthToken -ClientID $actionContext.Configuration.ClientId -ClientSecret $actionContext.Configuration.ClientSecret -TokenUrl $actionContext.Configuration.tokenUrl
    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    # Get all teams
    $actionMessage = 'querying teams'
    $teams = [System.Collections.Generic.List[object]]::new()
    $startIndex = 1
    $count = 25
    do {
        $splatParamsGetTeams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Groups?startIndex=$startIndex&count=$count"
            Method  = 'GET'
            Headers = $headers
        }
        $GetTeamsResponse = Invoke-EcareRestMethod @splatParamsGetTeams
        $receivedTeams = @($GetTeamsResponse.Resources).Count
        if ($receivedTeams -gt 0) {
            $teams.AddRange(@($GetTeamsResponse.Resources))
        }
        $startIndex += $receivedTeams
    } while ($receivedTeams -eq $count)
    Write-Information "Queried teams. Result count: $($teams.Count)"

    # The SCIM filter on groups is not supported by eCare (it returns all users), so retrieve all users once
    # Build a lookup to translate a team member (id, employeeNumber, externalId or userName) to the account reference (id)
    # and read the teams of each user (if eCare returns the groups attribute)
    $actionMessage = 'querying accounts'
    $accountLookup = @{}
    $teamMembers = @{}
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
            $lookupKeys = @(
                $user.id,
                $user.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.employeeNumber,
                $user.externalId,
                $user.userName
            )
            foreach ($lookupKey in ($lookupKeys | Where-Object { -not [string]::IsNullOrEmpty($_) })) {
                $lookupKey = "$lookupKey".Trim().ToLower()
                if (-not $accountLookup.ContainsKey($lookupKey)) {
                    $accountLookup[$lookupKey] = $user.id
                }
            }

            foreach ($userGroup in @($user.groups)) {
                # A team can be returned as a string or as a SCIM multi-valued object, register both the value (id) and the display name
                if ($userGroup -is [string]) {
                    $groupKeys = @($userGroup)
                }
                else {
                    $groupKeys = @($userGroup.value, $userGroup.display)
                }
                foreach ($groupKey in ($groupKeys | Where-Object { -not [string]::IsNullOrEmpty($_) })) {
                    $groupKey = $groupKey.Trim().ToLower()
                    if (-not $teamMembers.ContainsKey($groupKey)) {
                        $teamMembers[$groupKey] = [System.Collections.Generic.List[string]]::new()
                    }
                    $teamMembers[$groupKey].Add($user.id)
                }
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

    Write-Information "Queried accounts. Result count: $(@($accountLookup.Values | Select-Object -Unique).Count)"

    # Output permission entitlements with account references in batches to prevent exceeding maximum limits
    $actionMessage = 'outputting permission entitlements to HelloID (in batches of 500 account references)'
    $importedPermissionEntitlements = 0
    $unresolvedMembers = [System.Collections.Generic.List[string]]::new()
    $teamsWithMembers = 0
    $batchSize = 500
    foreach ($team in $teams) {
        # Members of the team, as returned in the members attribute of the team
        $resolvedMembers = foreach ($member in @($team.members)) {
            if ($null -eq $member) {
                continue
            }
            $memberValue = if ($member -is [string]) { $member } else { $member.value }
            if ([string]::IsNullOrEmpty($memberValue)) {
                continue
            }
            $accountReference = $accountLookup["$memberValue".Trim().ToLower()]
            if ([string]::IsNullOrEmpty($accountReference)) {
                $unresolvedMembers.Add("$memberValue")
                continue
            }
            $accountReference
        }
        if (@($team.members).Count -gt 0) {
            $teamsWithMembers++
        }

        # Members of the team, as returned in the groups attribute of the accounts
        $groupMembers = @(
            @($resolvedMembers) + @($teamMembers["$($team.id)".ToLower()]) + @($teamMembers["$($team.displayName)".Trim().ToLower()]) |
                Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique
        )

        # Make sure the displayName has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($team.displayName))) {
            $displayName = $($team.displayName).substring(0, [System.Math]::Min(100, $($team.displayName).Length))
        }
        else {
            $displayName = $team.id
        }
        $description = "Team - $displayName"
        $description = $description.substring(0, [System.Math]::Min(100, $description.Length))

        $permission = @{
            PermissionReference = @{
                Reference = $team.id
            }
            Description         = $description
            DisplayName         = $displayName
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

    if (($teamsWithMembers -eq 0) -and ($teamMembers.Count -eq 0)) {
        Write-Warning "No team members found. Neither the teams (members attribute) nor the accounts (groups attribute) contain memberships. Example team: $($teams[0] | ConvertTo-Json -Depth 3 -Compress)"
    }
    if ($unresolvedMembers.Count -gt 0) {
        $examples = @($unresolvedMembers | Select-Object -Unique -First 5) -join ', '
        Write-Warning "[$($unresolvedMembers.Count)] team members could not be matched to an account (on id, employeeNumber, externalId or userName) and are not imported. Examples: [$examples]"
    }

    Write-Information "eCare PUUR permission teams entitlement import completed. Teams: [$($teams.Count)]. Teams with members: [$teamsWithMembers]. Result count: [$importedPermissionEntitlements]"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-EcareError -ErrorObject $ex
        Write-Error "Could not import eCare PUUR permission teams entitlements. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Error "Could not import eCare PUUR permission teams entitlements. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}
