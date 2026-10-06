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
        'Clientadministratie Wachtlijst',
        'Clientadministratie Wachtlijstbeheer',
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
        'Wachtlijstrapportages',
        'Superuser',
        'Zorgmessenger Regisseur',
        'Zorgmessenger Serviceteam'
    )

    # Make sure to test with special characters and if needed; add utf8 encoding.
    foreach ($permission in $staticRoles) {
        $outputContext.Permissions.Add(
            @{
                DisplayName    = $permission
                Identification = @{
                    Reference   = $permission.ToLower()
                }
            }
        )
    }
} catch {
    Write-Warning "Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($_.InvocationInfo.Line). Error: $($_.Exception.Message)"
}
