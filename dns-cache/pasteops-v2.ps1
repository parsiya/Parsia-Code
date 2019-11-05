# Don't run this, copy/paste from it.
Clear-DnsClientCache
# Obviously replace this if you are looking to trace example.net
ping example.net
$dns1 = Get-DnsClientCache
# Run the application.
$dns2 = Get-DnsClientCache
Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1 -PassThru