###########################################################################
# NAME: cript to create FW Rules on Exchange 2013 servers
# AUTHOR:  yshen27
# COMMENT: 
# VERSION HISTORY:
# 1.0 5/05/2014 - Oscar, initial release
# 1.1 5/23/2014 - Updated disabling of builtin rules to use groups, added a couple of additional ports needed and created firewall group for all new rules
###########################################################################

clear
$ErrorActionPreference = "Stop"

[array]$lyncED = "10.0.0.10"
[array]$lyncFE = "10.0.0.20"
[array]$reverseProxies = "10.0.0.30"

foreach ($server in $lyncED){  
    #Lync Edge End 2013 Servers  
    $session = New-PSSession -ComputerName $server

    write-host " "
    write-host "Exchange 2013 Edge Server" -ForegroundColor Yellow
    write-host "Starting Remote Session..." -ForegroundColor Yellow

    Invoke-Command -Session $session -ScriptBlock{
        write-host "$($env:COMPUTERNAME)" -ForegroundColor Yellow -BackgroundColor Gray
        
        #disable built-in CS firewall rules
        Get-NetFirewallRule -Group "CS" | Set-NetFirewallRule -Enabled:false

        write-host "Standard Firewall Rules Disabled" -ForegroundColor Yellow -BackgroundColor Gray
        
        $FWruleExist = Get-NetFirewallRule 
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP443 (SIP/TLS)'})) {
            New-NetFirewallRule -DisplayName "TCP443 (SIP/TLS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 443 -RemotePort Any -group "SU-CS"
        }

        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP5269 (XMPP/TCP)'})){
            New-NetFireWallRule -DisplayName "TCP5269 (XMPP/TCP)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 5269 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP5061 (SIP/MTLS)'})){    
            New-NetFireWallRule -DisplayName "TCP5061 (SIP/MTLS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 5061 -RemotePort Any -group "SU-CS"
        }

        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP3478 (AV/UDP)'})){    
            New-NetFireWallRule -DisplayName "TCP3478 (AV/UDP)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol UDP -LocalPort 3478 -RemotePort Any -group "SU-CS"
        }
        
        write-host "New Firewall Rules created" -ForegroundColor Yellow -BackgroundColor Gray
        write-host "End of remote session" -ForegroundColor Yellow
        }

    Remove-PSSession $session
}

foreach ($server in $lyncFE){  
    #Lync Front End 2013 Servers
    $session = New-PSSession -ComputerName $server

    write-host " "
    write-host "Exchange 2013 Front End Server" -ForegroundColor Gray
    write-host "Starting Remote Session..." -ForegroundColor Gray

    Invoke-Command -Session $session -ScriptBlock{
        write-host "$($env:COMPUTERNAME)" -ForegroundColor White -BackgroundColor Gray
        
        #disable built-in CS firewall rules
        Get-NetFirewallRule -Group "CS" | Set-NetFirewallRule -Enabled:false

        write-host "Standard Firewall Rules Disabled" -ForegroundColor White -BackgroundColor Gray

        $FWruleExist = Get-NetFirewallRule 
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP4443 (HTTPS)'})){
            New-NetFireWallRule -DisplayName "TCP4443 (HTTPS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any  -RemoteAddress 128.230.0.0/16,10.0.0.0/8 -Protocol TCP -LocalPort 4443 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP443 (HTTPS)'})){
            New-NetFireWallRule -DisplayName "TCP443 (HTTPS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress 128.230.0.0/16 -Protocol TCP -LocalPort 443 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP80 (HLB)'})){
            New-NetFireWallRule -DisplayName "TCP80 (HLB)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress 128.230.0.0/16 -Protocol TCP -LocalPort 80 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP8080 (HLB)'})){
            New-NetFireWallRule -DisplayName "TCP8080 (HLB)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress 128.230.0.0/16 -Protocol TCP -LocalPort 8080 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP5061 (HLB + SIP/TLS)'})){
            New-NetFireWallRule -DisplayName "TCP5061 (HLB + SIP/TLS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress 128.230.0.0/16 -Protocol TCP -LocalPort 5061 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP5062 (SIP/MTLS)'})){
            New-NetFireWallRule -DisplayName "TCP5062 (SIP/MTLS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress 128.230.0.0/16 -Protocol TCP -LocalPort 5062 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP5086 (SIP/MTLS)'})){
            New-NetFireWallRule -DisplayName "TCP5086 (SIP/MTLS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 5086 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP5087 (SIP/MTLS)'})){
            New-NetFireWallRule -DisplayName "TCP5087 (SIP/MTLS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 5087 -RemotePort Any -group "SU-CS"
        }

        write-host "New Firewall Rules created" -ForegroundColor White -BackgroundColor Gray
        write-host "End of remote session" -ForegroundColor White
        }

    Remove-PSSession $session
}
     
foreach($server in $reverseProxies){
    #Lync Reversed Proxy Servers
    $session = New-PSSession -ComputerName $server

    write-host " "
    write-host "Exchange 2013 Reverse Proxies" -ForegroundColor Green
    write-host "Starting Remote Session..." -ForegroundColor Green

    Invoke-Command -Session $session -ScriptBlock{
        write-host "$($env:COMPUTERNAME).adng.syr.edu" -ForegroundColor Green -BackgroundColor Gray

        $FWruleExist = Get-NetFirewallRule 
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP443 (HTTPS)'})){    
             New-NetFireWallRule -DisplayName "TCP443 (HTTPS)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 443 -RemotePort Any -group "SU-CS"
        }
        if(![bool]($FWruleExist | where-object {$_.displayname -eq 'TCP80 (HTTPS)'})){    
             New-NetFireWallRule -DisplayName "TCP80 (HTTP)" -Direction Inbound -Profile Any -Enabled True -Action Allow -OverrideBlockRules $False -Program Any -LocalAddress Any -RemoteAddress Any -Protocol TCP -LocalPort 80 -RemotePort Any -group "SU-CS"
        }

        write-host "New FireWall Rules created" -ForegroundColor Green -BackgroundColor Gray
        write-host "End of remote session" -ForegroundColor Green
    }

    Remove-PSSession $session
}
write-host " "
write-host "End of Script" -ForegroundColor Blue -BackgroundColor Gray
