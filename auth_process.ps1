$processPath = get-process | select-object path
foreach ($path in $processPath)
{
    if ($path.Path -ne $null)
    {
        $authProcess = Get-AuthenticodeSignature $path.Path
        $authProcess
        if ($authProcess.Status -ne "Valid")
        {
            Add-Content .\invalid_process.txt $authProcess.Path
        }
    }
}