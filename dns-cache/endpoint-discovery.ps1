Write-Output "Clearing the DNS cache"
Clear-DnsClientCache
Write-Output "Pinging example.net to populate the DNS cache"
Invoke-Expression "ping example.net" | Out-Null
Write-Output "Creating a snapshot of the DNS cache"
$dns_before = Get-DnsClientCache
Read-Host "Start the application and interact with it. Press Enter when done"
Write-Output "Creating a snapshot of the DNS cache"
$dns_after = Get-DnsClientCache
Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1 -PassThru