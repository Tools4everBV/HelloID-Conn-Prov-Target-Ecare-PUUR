##################################################
# HelloID-Conn-Prov-Target-Ecare-Disable
# PowerShell V2
##################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions#region functions
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
            scope =   "Ecare.Service.SCIM"
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

            if ($Body){
                $splatParams['Body'] = $Body
            }
            Invoke-RestMethod @splatParams -Verbose:$false
        } catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
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

            if($property.Name -eq 'employeeNumber') {
               $modifiedObject | Add-Member @{ $($property.Name) = $SourceObject.$('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User').$($property.Name) }
            }
            elseif ($property.Name -eq 'WorkEmail') {

                foreach ($email in $SourceObject.emails) {
                    if ($email.type -eq "work") {
                        $modifiedObject | Add-Member @{ $($property.Name) = $email.value}
                        break
                    }
                }
            }
            else {
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
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    $accessToken = Get-GenericScimOAuthToken -ClientID $ActionContext.Configuration.ClientId -ClientSecret $ActionContext.Configuration.ClientSecret -TokenUrl $ActionContext.Configuration.tokenUrl
    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    Write-Information "Verifying if a Ecare account for [$($personContext.Person.DisplayName)] exists"
    try {
        $splatParams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users/$($actionContext.References.Account)"
            Method  = 'GET'
            Headers = $headers
        }
        $correlatedAccount = Invoke-EcareRestMethod @splatParams
        $outputContext.PreviousData = $correlatedAccount
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404){
            $action = 'NotFound'
        } else {
            throw $_
        }
    }

    if ($null -ne $correlatedAccount) {
		$splatCompareProperties = @{
            ReferenceObject  = @($correlatedAccount.PSObject.Properties)
            DifferenceObject = @(([PSCustomObject]$actionContext.Data).PSObject.Properties)
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($propertiesChanged) {
			$action = 'UpdateDisableAccount'
			$dryRunMessage = "Update and disable Ecare account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] will be executed during enforcement"
		}
		else
		{
			$action = 'DisableAccount'
			$dryRunMessage = "Disable Ecare account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] will be executed during enforcement"
		}
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
            'DisableAccount' {
                Write-Information "Disabling Ecare account with accountReference: [$($actionContext.References.Account)]"

                [System.Collections.Generic.List[object]]$operations = @()

                $operations.Add(
                    [PSCustomObject]@{
                        op = "Replace"
                        path = "active"
                        value = $False
                    }
                )

                $body = [ordered]@{
                    schemas = @(
                        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                    )
                    Operations = $operations
                }

                $splatParams = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users/$($actionContext.References.Account)"
                    Body    = $body | ConvertTo-Json
                    Method  = 'PATCH'
                    Headers = $headers
                }
                $null = Invoke-EcareRestMethod @splatParams

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'Disable account was successful'
                    IsError = $false
                })
                break
            }
			
			'UpdateDisableAccount' {
                Write-Information "Updating and disabling Ecare account with accountReference: [$($actionContext.References.Account)]"

                # Make sure to test with special characters and if needed; add utf8 encoding.
                $ecareUpdateAccount = $actionContext.Data | Select-Object -Property $propertiesChanged.Name
                $body = $ecareUpdateAccount | ConvertTo-ScimUpdateObject

                Write-Warning ($body | ConvertTo-Json)

                $splatParams = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users/$($actionContext.References.Account)"
                    Body    = $body | ConvertTo-Json
                    Method  = 'Patch'
                    Headers = $headers
                }

                Write-Warning "$($splatParams.Uri)"

                $UpdateResult = Invoke-EcareRestMethod @splatParams


                $outputContext.data = $actionContext.Data
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update and disable account was successful, Account property(s) updated: [$($propertiesChanged.name -join ',')]"
                        IsError = $false
                    })
                break
            }

            'NotFound' {
                $outputContext.Success  = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Ecare account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted, or the account is not correlated"
                    IsError = $false
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
        $auditMessage = "Could not disable Ecare account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not disable Ecare account. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
        Message = $auditMessage
        IsError = $true
    })
}
