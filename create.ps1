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

    $accessToken = Get-GenericScimOAuthToken -ClientID $ActionContext.Configuration.ClientId -ClientSecret $ActionContext.Configuration.ClientSecret -TokenUrl $ActionContext.Configuration.tokenUrl
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

        # Verify if a user must be either [created ] or just [correlated]

        $splatParams = @{
            Uri     = "$($ActionContext.Configuration.BaseUrl)/scim/Users?filter=username eq $($correlationValue)"
            Method  = 'Get'
            Headers = $headers
        }
        $webResponse = Invoke-EcareRestMethod @splatParams

        if ($webResponse.Resources.count -eq 1) {
            $correlatedAccount = $webResponse.Resources | Select-Object -First 1
        } elseif ($webResponse.Resources.count -gt 1) {
            throw "Multiple accounts are found for [$($ActionContext.References.Account)]"
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
                    Body        = ($body | ConvertTo-Json)
                    ContentType = 'application/json'
                }

                try {
                    $createdAccount = Invoke-RestMethod @splatCreate
                } catch {
                    if ($_.Exception.StatusCode -eq 'NotFound') {
                        throw "Employee [$($actionContext.Data.employeeNumber)] not found, Employee objects are not managed in this connector"
                    } else {
                        throw
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
                    $createdAccount = Invoke-RestMethod @splatDisable
                }

                $outputContext.Data = $createdAccount
                $outputContext.AccountReference = $createdAccount.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.employeeNumber
                $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                break
            }

            'CorrelateAccount' {
                Write-Information 'Correlating Ecare account'
                $outputContext.Data = $correlatedAccount
                $outputContext.AccountReference = $correlatedAccount.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.employeeNumber
                $outputContext.AccountCorrelated = $true
                $auditLogMessage = "Correlated account: [$($correlatedAccount.ExternalId)] on field: [$($correlationField)] with value: [$($correlationValue)]"
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
