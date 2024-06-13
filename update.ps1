#################################################
# HelloID-Conn-Prov-Target-Ecare-Update
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
            "content-type" = "application/x-www-form-urlencoded"
        }

        $body = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            grant_type    = "client_credentials"
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

function ConvertTo-ScimUpdateObject {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            ValueFromPipeline = $True,
            Position = 0)]
        $EcareAccount
    )

    [System.Collections.Generic.List[object]]$operations = @()
    foreach ($property in $EcareAccount.PSObject.Properties) {
        if ($property.Name -eq "WorkEmail") {
            $operations.Add(
                [PSCustomObject]@{
                    op    = "Replace"
                    path  = "emails"
                    value = $property.Value
                }
            )
        } else {
            $operations.Add(
                [PSCustomObject]@{
                    op    = "Replace"
                    path  = $property.Name
                    value = $property.Value
                }
            )
        }
    }
    $body = [ordered]@{
        schemas    = @(
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        )
        Operations = $operations
    }
    write-output $body
}

function ConvertTo-AccountObject {
    param(
        [parameter(Mandatory)]
        [PSCustomObject]
        $AccountModel,

        [parameter( Mandatory,
            ValueFromPipeline = $True)]
        [PSCustomObject]
        $SourceObject
    )
    try {
        $modifiedObject = [PSCustomObject]@{}
        foreach ($property in $AccountModel.PSObject.Properties) {

            if ($property.Name -eq 'employeeNumber') {
                $modifiedObject | Add-Member @{ $($property.Name) = $SourceObject.$('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User').$($property.Name) }
            } elseif ($property.Name -eq 'WorkEmail') {

                foreach ($email in $SourceObject.emails) {
                    if ($email.type -eq "work") {
                        $modifiedObject | Add-Member @{ $($property.Name) = $email.value }
                        break
                    }
                }
            } else {
                $modifiedObject | Add-Member @{ $($property.Name) = $SourceObject.$($property.Name) }
            }

        }
        Write-Output $modifiedObject
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
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

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    $accessToken = Get-GenericScimOAuthToken -ClientID $ActionContext.Configuration.ClientId -ClientSecret $ActionContext.Configuration.ClientSecret -TokenUrl $ActionContext.Configuration.tokenUrl

    Write-Information "Verifying if a Ecare account for [$($personContext.Person.DisplayName)] exists"

    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $splatParams = @{
        Method  = 'Get'
        Uri     = "$($ActionContext.Configuration.BaseUrl)/scim/Users?filter=username eq $($ActionContext.References.Account)"
        Headers = $headers
    }

    $webResponse = Invoke-EcareRestMethod @splatParams
    if ($null -ne $webResponse.Resources) {
        if ($webResponse.Resources.count -eq 1) {
            $ScimAccount = $webResponse.Resources[0]
            $correlatedAccount = $ScimAccount | ConvertTo-AccountObject -AccountModel $actionContext.data
        }
    }

    $outputContext.PreviousData = $correlatedAccount

    # Always compare the account against the current account in target system
    if ($null -ne $correlatedAccount) {
        $splatCompareProperties = @{
            ReferenceObject  = @($correlatedAccount.PSObject.Properties)
            DifferenceObject = @(([PSCustomObject]$actionContext.Data).PSObject.Properties)
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($propertiesChanged) {
            $action = 'UpdateAccount'
            $dryRunMessage = "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"
        } else {
            $action = 'NoChanges'
            $dryRunMessage = 'No changes will be made to the account during enforcement'
        }
    } else {
        $action = 'NotFound'
        $dryRunMessage = "Ecare account for: [$($personContext.Person.DisplayName)] not found. Possibly deleted."
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $dryRunMessage"
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'UpdateAccount' {
                Write-Information "Updating Ecare account with accountReference: [$($actionContext.References.Account)]"

                # Make sure to test with special characters and if needed; add utf8 encoding.
                $ecareUpdateAccount = $actionContext.Data | Select-Object -Property $propertiesChanged.Name
                $body = $ecareUpdateAccount | ConvertTo-ScimUpdateObject

                $splatParams = @{
                    Uri     = "$($ActionContext.Configuration.BaseUrl)/scim/Users/$($ScimAccount.id)"
                    Body    = $body | ConvertTo-Json
                    Method  = 'Patch'
                    Headers = $headers
                }

                $UpdateResult = Invoke-EcareRestMethod @splatParams


                $outputContext.data = $actionContext.Data
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged.name -join ',')]"
                        IsError = $false
                    })
                break
            }

            'NoChanges' {
                Write-Information "No changes to Ecare account with accountReference: [$($actionContext.References.Account)]"

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = 'No changes will be made to the account during enforcement'
                        IsError = $false
                    })
                break
            }

            'NotFound' {
                $outputContext.Success = $false
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Ecare account with accountReference: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted, or the account is not correlated"
                        IsError = $true
                    })
                break
            }
        }
    }
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-EcareError -ErrorObject $ex
        $auditMessage = "Could not update Ecare account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Ecare account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
