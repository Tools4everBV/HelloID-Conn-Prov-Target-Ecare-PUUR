################################################################
# HelloID-Conn-Prov-Target-Ecare-GrantPermission-Group
# PowerShell V2
################################################################

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

    } catch {
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
        } catch {
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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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
        } catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
#endregion

# Begin
try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    Write-Information "Verifying if a Ecare account for [$($personContext.Person.DisplayName)] exists"
    $accessToken = Get-GenericScimOAuthToken -ClientID $ActionContext.Configuration.ClientId -ClientSecret $ActionContext.Configuration.ClientSecret -TokenUrl $ActionContext.Configuration.tokenUrl
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    
    $splatParams = @{
        Uri     = "$($ActionContext.Configuration.BaseUrl)/scim/Users?filter=username eq $($ActionContext.References.Account)"
        Method  = 'Get'
        Headers = $headers
    }
    $webResponse = Invoke-EcareRestMethod @splatParams

    if ($webResponse.Resources.count -eq 1) {
        $correlatedAccount = $webResponse.Resources | Select-Object -First 1
    } elseif ($webResponse.Resources.count -gt 1) {
        throw "Multiple accounts are found for [$($ActionContext.References.Account)]"
    }



    if ($null -ne $correlatedAccount) {
        $action = 'GrantPermission'
        $dryRunMessage = "Grant Ecare permission: [$($actionContext.References.Permission.DisplayName)] will be executed during enforcement"
    } else {
        $action = 'NotFound'
        $dryRunMessage = "Ecare account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted, or the account is not correlated"
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $dryRunMessage"
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'GrantPermission' {
                Write-Information "Granting Ecare permission: [$($actionContext.References.Permission.DisplayName)] - [$($actionContext.References.Permission.Reference)]"

                # Make sure to test with special characters and if needed; add utf8 encoding.
                $bodyRoles = @{
                    Schemas    = @(
                        'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                    )
                    Operations = @(
                        @{
                            op    = 'Add'
                            path  = 'roles'
                            value = "$($actionContext.References.Permission.Reference)"
                        }
                    )
                }
                $splatRoles = @{
                    Uri         = "$($actionContext.Configuration.BaseUrl)/scim/Users/$($correlatedAccount.id)"
                    Method      = 'Patch'
                    Headers     = $headers
                    Body        = ($bodyRoles | ConvertTo-Json)
                    ContentType = 'application/json'
                }
                $null = Invoke-RestMethod @splatRoles

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Grant permission [$($actionContext.References.Permission.DisplayName)] was successful"
                        IsError = $false
                    })
            }

            'NotFound' {
                $outputContext.Success = $false
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Ecare account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted, or the account is not correlated"
                        IsError = $true
                    })
                break
            }
        }
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-EcareError -ErrorObject $ex
        $auditMessage = "Could not grant Ecare permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not grant Ecare permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}