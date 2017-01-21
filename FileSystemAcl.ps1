# Configure Powershell Environment
[System.Management.Automation.ScriptBlock]$SetupRunpaceDefaults = {
                                                                    Set-StrictMode -Version Latest
                                                                    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                                                                    $WarningPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                                                                   }

#Setup Runspace Defaults
Invoke-Command -ScriptBlock $SetupRunpaceDefaults -NoNewScope


function Main{

   Remove-FileSystemACL -Path "C:\CCDC\Test" -UserOrGroup "ad\yicheng" -ACLType Allow

   Add-FileSystemACL -Path "C:\CCDC\Test" -UserOrGroup "ad\yicheng" -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl -bxor [System.Security.AccessControl.FileSystemRights]::Delete) -ACLType Allow -ACLAppliesTo SubfolderAndFilesOnly -RemoveAllExistingACL $true
 

}


function Add-FileSystemACL{

	[CmdletBinding()]
	Param
	(
			[Parameter(Mandatory=$true)][System.String]$Path,
			[Parameter(Mandatory=$true)][System.Security.Principal.NTAccount]$UserOrGroup,
			[Parameter(Mandatory=$true)][System.Security.AccessControl.FileSystemRights]$Rights,
            [Parameter(Mandatory=$true)][System.Security.AccessControl.AccessControlType]$ACLType,
            [Parameter(Mandatory=$false)][FileSystemACLAppliesTo]$ACLAppliesTo = [FileSystemACLAppliesTo]::ThisFolderSubfoldersAndFiles,
            [Parameter(Mandatory=$false)][System.Boolean]$RemoveAllExistingACL = $false

	)

    [System.Security.AccessControl.FileSystemAccessRule] $objACE = Create-FileSystemACE -UserOrGroup $UserOrGroup -Rights $Rights -ACLType $ACLType -ACLAppliesTo $ACLAppliesTo
		
    #Get the ACL on the path
    $objACL = Get-ACL -Path $Path

    #Will remove all exists ACLs when adding the new ACL
    if ($RemoveAllExistingACL){

        $objACL.RemoveAccessRuleAll({New-Object System.Security.AccessControl.FileSystemAccessRule("reset",[System.Security.AccessControl.FileSystemRights]::Read,[System.Security.AccessControl.AccessControlType]::Allow)})
        
        $objACL.RemoveAccessRuleAll({New-Object System.Security.AccessControl.FileSystemAccessRule("reset",[System.Security.AccessControl.FileSystemRights]::Read,[System.Security.AccessControl.AccessControlType]::Deny)})

    }

    #Add the access rule
	$objACL.AddAccessRule($objACE)

    Set-ACL -Path $Path -AclObject $objACL


	}


function Remove-FileSystemACL{

	[CmdletBinding()]
	Param
	(
			[Parameter(Mandatory=$true)][System.String]$Path,
			[Parameter(Mandatory=$true)][System.Security.Principal.NTAccount]$UserOrGroup,
            [Parameter(Mandatory=$false)][System.Security.AccessControl.AccessControlType]$ACLType
    )

	[System.Security.AccessControl.FileSystemAccessRule] $objACE = Create-FileSystemACE -UserOrGroup $UserOrGroup -Rights Read -ACLType $ACLType -ACLAppliesTo ThisFolderSubfoldersAndFiles

    #Get the ACL on the path
    $objACL = Get-ACL -Path $Path

    #Add the access rule
	$objACL.RemoveAccessRuleAll($objACE)

    Set-ACL -Path $Path -AclObject $objACL


	}

function Create-FileSystemACE{

	[CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSystemAccessRule])]
	Param
	(
			[Parameter(Mandatory=$true)][System.Security.Principal.NTAccount]$UserOrGroup,
			[Parameter(Mandatory=$true)][System.Security.AccessControl.FileSystemRights]$Rights,
            [Parameter(Mandatory=$true)][System.Security.AccessControl.AccessControlType]$ACLType,
            [Parameter(Mandatory=$true)][FileSystemACLAppliesTo]$ACLAppliesTo			
	)

    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlag = $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit;
    [System.Security.AccessControl.PropagationFlags]$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None

   switch (($ACLAppliesTo).value__)
   {
     # ThisFolderOnly = 0,
      0 {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None}
      
      # ThisFolderSubfoldersAndFiles = 1,
      1 {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None}
      
      # ThisFolderAndSubFolders = 2,
      2  {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None}
      
      # ThisFolderAndFiles = 3,
      3  {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None}
            
      # SubfolderAndFilesOnly = 4,
      4  {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit -bor [System.Security.AccessControl.PropagationFlags]::InheritOnly}
            
      # SubfoldersOnly = 5,
      5  {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly}
            
      #FilesOnly = 6
      6  {$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit; $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly}
            
   }
   
   [System.Security.AccessControl.FileSystemAccessRule] $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($UserOrGroup, $Rights, $InheritanceFlag, $PropagationFlag, $ACLType)

   return $objACE

}


Add-Type -TypeDefinition @"
   //Folder security progataion
   public enum FileSystemACLAppliesTo
   {
      ThisFolderOnly = 0,
      ThisFolderSubfoldersAndFiles = 1,
      ThisFolderAndSubFolders = 2,
      ThisFolderAndFiles = 3,
      SubfolderAndFilesOnly = 4,
      SubfoldersOnly = 5,
      FilesOnly = 6
   }
"@



#Call Main
main

