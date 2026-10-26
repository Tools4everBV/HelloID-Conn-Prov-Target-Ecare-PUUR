#################################################
# HelloID-Conn-Prov-Target-Ecare-Import
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
    Write-Information 'Starting eCare PUUR account entitlement import'

    # Set authentication headers
    $accessToken = Get-GenericScimOAuthToken -ClientID $actionContext.Configuration.ClientId -ClientSecret $actionContext.Configuration.ClientSecret -TokenUrl $actionContext.Configuration.tokenUrl
    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $take = 100
    $skip = 1 # SCIM uses 1-based index
    $moreRecords = $true
    $accountCount = 0

    while ($moreRecords) {
        $splatGetAccounts = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users?startIndex=$skip&count=$take"
            Method  = 'GET'
            Headers = $headers
        }
    
        $GetResponse = (Invoke-EcareRestMethod @splatGetAccounts)

        foreach ($importedAccount in $GetResponse.Resources) {
            # Map the SCIM object to the field names of the fieldMapping, HelloID uses these names (e.g. Data.employeeNumber) for correlation
            $workEmail = @($importedAccount.emails | Where-Object { $_.type -eq 'work' })[0].value
            if ([string]::IsNullOrEmpty($workEmail)) {
                $workEmail = @($importedAccount.emails)[0].value
            }
            $data = @{
                id             = $importedAccount.id
                ExternalId     = $importedAccount.externalId
                userName       = $importedAccount.userName
                WorkEmail      = $workEmail
                active         = $importedAccount.active
                employeeNumber = $importedAccount.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.employeeNumber
            }

            # Make sure the UserName has a value of max 100 char
            if (-not([string]::IsNullOrEmpty($importedAccount.userName))) {
                $userName = $($importedAccount.userName).substring(0, [System.Math]::Min(100, $($importedAccount.userName).Length))
            }
            else {
                $userName = $importedAccount.id
            }

            # Make sure the DisplayName has a value of max 100 char
            if (-not([string]::IsNullOrEmpty($importedAccount.displayName))) {
                $displayName = $($importedAccount.displayName).substring(0, [System.Math]::Min(100, $($importedAccount.displayName).Length))
            }
            elseif (-not([string]::IsNullOrEmpty($importedAccount.name.formatted))) {
                $displayName = $($importedAccount.name.formatted).substring(0, [System.Math]::Min(100, $($importedAccount.name.formatted).Length))
            }
            else {
                $displayName = $userName
            }

            # Return the result
            Write-Output @{
                AccountReference = $importedAccount.id
                DisplayName      = $displayName
                UserName         = $userName
                Enabled          = ($importedAccount.active -eq $true)
                Data             = $data
            }
            $accountCount++
        }

        # Stop when the last page is reached, totalResults is not reliable so check the number of returned resources
        if (@($GetResponse.Resources).Count -lt $take) {
            $moreRecords = $false
        }
        else {
            $skip += $take
        }
    }

    Write-Information "eCare PUUR account entitlement import completed. Successfully queried [$accountCount] existing accounts"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-EcareError -ErrorObject $ex
        Write-Error "Could not import eCare PUUR account entitlements. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Error "Could not import eCare PUUR account entitlements. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}
