#################################################
# HelloID-Conn-Prov-Target-Ecare-Create
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

function ConvertTo-AccountObject {
    # Converts the SCIM account object to an object with the field names of the fieldMapping
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
                $value = $SourceObject.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.employeeNumber
            }
            elseif ($property.Name -eq 'WorkEmail') {
                $value = @($SourceObject.emails | Where-Object { $_.type -eq 'work' })[0].value
            }
            else {
                $value = $SourceObject.$($property.Name)
            }
            $modifiedObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $value
        }
        Write-Output $modifiedObject
    }
    catch {
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
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    $accessToken = Get-GenericScimOAuthToken -ClientID $actionContext.Configuration.ClientId -ClientSecret $actionContext.Configuration.ClientSecret -TokenUrl $actionContext.Configuration.tokenUrl
    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.accountField
        $correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        # Translate the account correlation field (field name of the fieldMapping) to the SCIM attribute
        switch ($correlationField) {
            'employeeNumber' { $scimAttribute = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber' }
            'ExternalId' { $scimAttribute = 'externalId' }
            'userName' { $scimAttribute = 'userName' }
            default { throw "Correlation on field [$correlationField] is not supported. Use employeeNumber, ExternalId or userName" }
        }

        # Verify if a user must be either [created ] or just [correlated]
        $splatParams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/scim/Users?filter=$scimAttribute eq $([System.Uri]::EscapeDataString($correlationValue))"
            Method  = 'Get'
            Headers = $headers
        }
        $webResponse = Invoke-EcareRestMethod @splatParams

        if (@($webResponse.Resources).Count -eq 1) {
            $correlatedAccount = @($webResponse.Resources)[0]

            # Make sure the filter is applied by eCare, so an account is never correlated on a wrong value
            $correlatedAccountValue = ($correlatedAccount | ConvertTo-AccountObject -AccountModel ([PSCustomObject]@{ $correlationField = $null })).$correlationField
            if ("$correlatedAccountValue" -ne "$correlationValue") {
                throw "The account found for $correlationField [$correlationValue] has a different value [$correlatedAccountValue]. The filter is possibly not supported by eCare"
            }
        } elseif (@($webResponse.Resources).Count -gt 1) {
            throw "Multiple accounts are found where $correlationField is: [$correlationValue]"
        }
    }

    if ($null -ne $correlatedAccount) {
        $action = 'CorrelateAccount'
    } else {
        $action = 'CreateAccount'
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Information "[DryRun] $action Ecare account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
        if ($action -eq 'CorrelateAccount') {
            $outputContext.Data = $correlatedAccount | ConvertTo-AccountObject -AccountModel ([PSCustomObject]$actionContext.Data)
            $outputContext.AccountReference = $correlatedAccount.id
        }
        $outputContext.Success = $true
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = $action
                Message = "[DryRun] $action Ecare account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
                IsError = $false
            })
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'CreateAccount' {
                Write-Information 'Creating and correlating Ecare account'
                $body = [ordered]@{
                    schemas                                                      = @(
                        'urn:ietf:params:scim:schemas:core:2.0:User',
                        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'
                    )
                    userName                                                     = $actionContext.Data.userName
                    externalId                                                   = $actionContext.Data.externalId
                    emails                                                       = @(
                        [ordered]@{
                            type    = 'work'
                            primary = $true
                            value   = $actionContext.Data.WorkEmail
                        }
                    )
                    roles                                                        = @()
                    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' = @{
                        employeeNumber = $actionContext.Data.employeeNumber
                    }
                }

                $splatCreate = @{
                    Uri         = "$($actionContext.Configuration.BaseUrl)/scim/Users"
                    Method      = 'POST'
                    Headers     = $headers
                    Body        = ($body | ConvertTo-Json -Depth 10)
                    ContentType = 'application/json'
                }

                $createError = $null
                try {
                    $createdAccount = Invoke-EcareRestMethod @splatCreate
                } catch {
                    $createError = $_
                    $statusCode = [int]$createError.Exception.Response.StatusCode
                    $errorDetails = if (-not [string]::IsNullOrEmpty($createError.ErrorDetails.Message)) { $createError.ErrorDetails.Message } else { $createError.Exception.Message }
                }

                # eCare can return an error (or no account) while the account is created, so verify if the account exists after all
                if (($null -eq $createdAccount.id) -and ($actionContext.CorrelationConfiguration.Enabled)) {
                    $retryResponse = Invoke-EcareRestMethod @splatParams
                    $retryAccount = @($retryResponse.Resources | Where-Object {
                            "$(($_ | ConvertTo-AccountObject -AccountModel ([PSCustomObject]@{ $correlationField = $null })).$correlationField)" -eq "$correlationValue"
                        })
                    if ($retryAccount.Count -eq 1) {
                        Write-Warning "eCare did not return the created account, but the account is found where $correlationField is: [$correlationValue]. Error: $errorDetails"
                        $createdAccount = $retryAccount[0]
                    }
                }

                if ($null -eq $createdAccount.id) {
                    # eCare returns a 404 or 500 when the employee does not exist, the 500 is also returned for other errors (e.g. a userName that is already in use)
                    if ($null -eq $createError) {
                        throw "eCare did not return the created account for employee [$($actionContext.Data.employeeNumber)]"
                    } elseif ($statusCode -eq 404) {
                        throw "Employee [$($actionContext.Data.employeeNumber)] not found, Employee objects are not managed in this connector. Error: $errorDetails"
                    } elseif ($statusCode -eq 500) {
                        throw "eCare returned an internal server error. Verify that employee [$($actionContext.Data.employeeNumber)] exists (Employee objects are not managed in this connector) and that the userName and email address are not already in use. Error: $errorDetails"
                    } else {
                        throw $createError
                    }
                }

                if ($actionContext.Data.active -eq $false) {
                    Write-Information 'Disable the account for the newly created user.'
                    $bodyDisable = @{
                        Schemas    = @(
                            'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                        )
                        Operations = @(
                            @{
                                op    = 'replace'
                                path  = 'active'
                                value = 'false'
                            }
                        )
                    }
                    $splatDisable = @{
                        Uri         = "$($actionContext.Configuration.BaseUrl)/scim/Users/$($createdAccount.id)"
                        Method      = 'Patch'
                        Headers     = $headers
                        Body        = ($bodyDisable | ConvertTo-Json)
                        ContentType = "application/json"
                    }
                    $disabledAccount = Invoke-EcareRestMethod @splatDisable

                    # Only use the response when eCare returns the account, so the account reference is never lost
                    if ($null -ne $disabledAccount.id) {
                        $createdAccount = $disabledAccount
                    }
                }

                # Convert the SCIM account to the field names of the fieldMapping (arrays and nested objects are not supported in the account data)
                $outputContext.Data = $createdAccount | ConvertTo-AccountObject -AccountModel ([PSCustomObject]$actionContext.Data)
                $outputContext.AccountReference = $createdAccount.id
                $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                break
            }

            'CorrelateAccount' {
                Write-Information 'Correlating Ecare account'
                # Convert the SCIM account to the field names of the fieldMapping (arrays and nested objects are not supported in the account data)
                $outputContext.Data = $correlatedAccount | ConvertTo-AccountObject -AccountModel ([PSCustomObject]$actionContext.Data)
                $outputContext.AccountReference = $correlatedAccount.id
                $outputContext.AccountCorrelated = $true
                $auditLogMessage = "Correlated account: [$($correlatedAccount.id)] on field: [$($correlationField)] with value: [$($correlationValue)]"
                break
            }
        }

        $outputContext.success = $true
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = $action
                Message = $auditLogMessage
                IsError = $false
            })
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-EcareError -ErrorObject $ex
        $auditMessage = "Could not create or correlate Ecare account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not create or correlate Ecare account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
