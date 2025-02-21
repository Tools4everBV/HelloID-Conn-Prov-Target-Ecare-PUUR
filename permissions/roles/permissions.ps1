############################################################
# HelloID-Conn-Prov-Target-Ecare-Permissions-Group
# PowerShell V2
############################################################

try {
    $staticRoles = @(
        'Accountbeheer',
        'Administratie-client',
        'Administratie-medewerker',
        'Clienten',
        'Coach',
        'Coordinator',
        'Declareren',
        'Documentbeheer',
        'Medewerker',
        'Pleinauteur',
        'Roosteraar',
        'Superuser'
    )

    # Make sure to test with special characters and if needed; add utf8 encoding.
    foreach ($permission in $staticRoles) {
        $outputContext.Permissions.Add(
            @{
                DisplayName    = $permission
                Identification = @{
                    DisplayName = $permission
                    Reference   = $permission.ToLower()
                }
            }
        )
    }
} catch {
    Write-Warning "Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($_.InvocationInfo.Line). Error: $($_.Exception.Message)"
}
