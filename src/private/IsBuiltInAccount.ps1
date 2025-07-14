# Function to check if the user is a built-in Windows account
function IsBuiltInAccount {
    param ($accountName)

    # Define built-in Windows accounts to filter out
    $builtInAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')

    # Check if the account matches a built-in account or pattern like DWM-*, UMFD-*
    return ($builtInAccounts -contains $accountName -or $accountName -match '^DWM-' -or $accountName -match '^UMFD-')
}