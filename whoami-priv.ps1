# Credits to github.com/proxb/PoshPrivilege
# Here is the minimal script to get the output of "whoami /priv"
# -------------------------------------
# Defining types & enums
$Domain = [AppDomain]::CurrentDomain
$DynAssembly = New-Object System.Reflection.AssemblyName('PrivilegeEnumAssembly')
$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('PrivilegeEnumModule', $False)
$EnumBuilder = $ModuleBuilder.DefineEnum('ProcessAccessFlags', 'Public', [uint32])
[void]$EnumBuilder.DefineLiteral('All', [uint32] 0x001F0FFF)
[void]$EnumBuilder.DefineLiteral('Terminate', [uint32] 0x00000001)
[void]$EnumBuilder.DefineLiteral('CreateThread', [uint32] 0x00000002)
[void]$EnumBuilder.DefineLiteral('VirtualMemoryOperation', [uint32] 0x00000008)
[void]$EnumBuilder.DefineLiteral('VirtualMemoryRead', [uint32] 0x00000010)
[void]$EnumBuilder.DefineLiteral('VirtualMemoryWrite', [uint32] 0x00000020)
[void]$EnumBuilder.DefineLiteral('DuplicateHandle', [uint32] 0x00000040)
[void]$EnumBuilder.DefineLiteral('CreateProcess', [uint32] 0x000000080)
[void]$EnumBuilder.DefineLiteral('SetQuota', [uint32] 0x00000100)
[void]$EnumBuilder.DefineLiteral('SetInformation', [uint32] 0x00000200)
[void]$EnumBuilder.DefineLiteral('QueryInformation', [uint32] 0x00000400)
[void]$EnumBuilder.DefineLiteral('QueryLimitedInformation', [uint32] 0x00001000)
[void]$EnumBuilder.DefineLiteral('Synchronize', [uint32] 0x00100000)
[void]$EnumBuilder.CreateType()
$EnumBuilder = $ModuleBuilder.DefineEnum('TOKEN_INFORMATION_CLASS', 'Public', [uint32])
[void]$EnumBuilder.DefineLiteral('TokenUser ',[uint32] 0x00000001)
[void]$EnumBuilder.DefineLiteral('TokenGroups',[uint32] 0x00000002)
[void]$EnumBuilder.DefineLiteral('TokenPrivileges',[uint32] 0x00000003)
[void]$EnumBuilder.DefineLiteral('TokenOwner',[uint32] 0x00000004)
[void]$EnumBuilder.DefineLiteral('TokenPrimaryGroup',[uint32] 0x00000005)
[void]$EnumBuilder.DefineLiteral('TokenDefaultDacl',[uint32] 0x00000006)
[void]$EnumBuilder.DefineLiteral('TokenSource',[uint32] 0x00000007)
[void]$EnumBuilder.DefineLiteral('TokenType',[uint32] 0x00000008)
[void]$EnumBuilder.DefineLiteral('TokenImpersonationLevel',[uint32] 0x00000009)
[void]$EnumBuilder.DefineLiteral('TokenStatistics',[uint32] 0x0000000a)
[void]$EnumBuilder.DefineLiteral('TokenRestrictedSids',[uint32] 0x0000000b)
[void]$EnumBuilder.DefineLiteral('TokenSessionId',[uint32] 0x0000000c)
[void]$EnumBuilder.DefineLiteral('TokenGroupsAndPrivileges',[uint32] 0x0000000d)
[void]$EnumBuilder.DefineLiteral('TokenSessionReference',[uint32] 0x0000000e)
[void]$EnumBuilder.DefineLiteral('TokenSandBoxInert',[uint32] 0x0000000f)
[void]$EnumBuilder.DefineLiteral('TokenAuditPolicy',[uint32] 0x00000010)
[void]$EnumBuilder.DefineLiteral('TokenOrigin',[uint32] 0x00000011)
[void]$EnumBuilder.CreateType()
$EnumBuilder = $ModuleBuilder.DefineEnum('Privileges', 'Public', [uint32])
[void]$EnumBuilder.DefineLiteral('SeAssignPrimaryTokenPrivilege',[uint32] 0x00000000)
[void]$EnumBuilder.DefineLiteral('SeAuditPrivilege',[uint32] 0x00000001)
[void]$EnumBuilder.DefineLiteral('SeBackupPrivilege',[uint32] 0x00000002)
[void]$EnumBuilder.DefineLiteral('SeBatchLogonRight',[uint32] 0x00000003)
[void]$EnumBuilder.DefineLiteral('SeChangeNotifyPrivilege',[uint32] 0x00000004)
[void]$EnumBuilder.DefineLiteral('SeCreateGlobalPrivilege',[uint32] 0x00000005)
[void]$EnumBuilder.DefineLiteral('SeCreatePagefilePrivilege',[uint32] 0x00000006)
[void]$EnumBuilder.DefineLiteral('SeCreatePermanentPrivilege',[uint32] 0x00000007)
[void]$EnumBuilder.DefineLiteral('SeCreateSymbolicLinkPrivilege',[uint32] 0x00000008)
[void]$EnumBuilder.DefineLiteral('SeCreateTokenPrivilege',[uint32] 0x00000009)
[void]$EnumBuilder.DefineLiteral('SeDebugPrivilege',[uint32] 0x0000000a)
[void]$EnumBuilder.DefineLiteral('SeImpersonatePrivilege',[uint32] 0x0000000b)
[void]$EnumBuilder.DefineLiteral('SeIncreaseBasePriorityPrivilege',[uint32] 0x0000000c)
[void]$EnumBuilder.DefineLiteral('SeIncreaseQuotaPrivilege',[uint32] 0x0000000d)
[void]$EnumBuilder.DefineLiteral('SeInteractiveLogonRight',[uint32] 0x0000000e)
[void]$EnumBuilder.DefineLiteral('SeLoadDriverPrivilege',[uint32] 0x0000000f)
[void]$EnumBuilder.DefineLiteral('SeLockMemoryPrivilege',[uint32] 0x00000010)
[void]$EnumBuilder.DefineLiteral('SeMachineAccountPrivilege',[uint32] 0x00000011)
[void]$EnumBuilder.DefineLiteral('SeManageVolumePrivilege',[uint32] 0x00000012)
[void]$EnumBuilder.DefineLiteral('SeNetworkLogonRight',[uint32] 0x00000013)
[void]$EnumBuilder.DefineLiteral('SeProfileSingleProcessPrivilege',[uint32] 0x00000014)
[void]$EnumBuilder.DefineLiteral('SeRemoteInteractiveLogonRight',[uint32] 0x00000015)
[void]$EnumBuilder.DefineLiteral('SeRemoteShutdownPrivilege',[uint32] 0x00000016)
[void]$EnumBuilder.DefineLiteral('SeRestorePrivilege',[uint32] 0x00000017)
[void]$EnumBuilder.DefineLiteral('SeSecurityPrivilege',[uint32] 0x00000018)
[void]$EnumBuilder.DefineLiteral('SeServiceLogonRight',[uint32] 0x00000019)
[void]$EnumBuilder.DefineLiteral('SeShutdownPrivilege',[uint32] 0x0000001a)
[void]$EnumBuilder.DefineLiteral('SeSystemEnvironmentPrivilege',[uint32] 0x0000001b)
[void]$EnumBuilder.DefineLiteral('SeSystemProfilePrivilege',[uint32] 0x0000001c)
[void]$EnumBuilder.DefineLiteral('SeSystemtimePrivilege',[uint32] 0x0000001d)
[void]$EnumBuilder.DefineLiteral('SeTakeOwnershipPrivilege',[uint32] 0x0000001e)
[void]$EnumBuilder.DefineLiteral('SeTcbPrivilege',[uint32] 0x0000001f)
[void]$EnumBuilder.DefineLiteral('SeTimeZonePrivilege',[uint32] 0x00000020)
[void]$EnumBuilder.DefineLiteral('SeUndockPrivilege',[uint32] 0x00000021)
[void]$EnumBuilder.DefineLiteral('SeDenyNetworkLogonRight',[uint32] 0x00000022)
[void]$EnumBuilder.DefineLiteral('SeDenyBatchLogonRight',[uint32] 0x00000023)
[void]$EnumBuilder.DefineLiteral('SeDenyServiceLogonRight',[uint32] 0x00000024)
[void]$EnumBuilder.DefineLiteral('SeDenyInteractiveLogonRight',[uint32] 0x00000025)
[void]$EnumBuilder.DefineLiteral('SeSyncAgentPrivilege',[uint32] 0x00000026)
[void]$EnumBuilder.DefineLiteral('SeEnableDelegationPrivilege',[uint32] 0x00000027)
[void]$EnumBuilder.DefineLiteral('SeDenyRemoteInteractiveLogonRight',[uint32] 0x00000028)
[void]$EnumBuilder.DefineLiteral('SeTrustedCredManAccessPrivilege',[uint32] 0x00000029)
[void]$EnumBuilder.DefineLiteral('SeIncreaseWorkingSetPrivilege',[uint32] 0x0000002a)
[void]$EnumBuilder.DefineLiteral('SeDelegateSessionUserImpersonatePrivilege',[uint32] 0x0000002b)
[void]$EnumBuilder.CreateType()

$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
$STRUCT_TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
[void]$STRUCT_TypeBuilder.DefineField('LowPart', [uint32], 'Public')
[void]$STRUCT_TypeBuilder.DefineField('HighPart', [int], 'Public')
[void]$STRUCT_TypeBuilder.CreateType()

$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
$STRUCT_TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
[void]$STRUCT_TypeBuilder.DefineField('Luid', [LUID], 'Public')
[void]$STRUCT_TypeBuilder.DefineField('Attributes', [uint32], 'Public')
[void]$STRUCT_TypeBuilder.CreateType()

$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
$STRUCT_TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType])
[void]$STRUCT_TypeBuilder.DefineField('PrivilegeCount', [uint32], 'Public')
[void]$STRUCT_TypeBuilder.DefineField('Privileges', [LUID_AND_ATTRIBUTES], 'Public')
[void]$STRUCT_TypeBuilder.CreateType()


$TypeBuilder = $ModuleBuilder.DefineType('PoShPrivilege', 'Public, Class')
$PInvokeMethod = $TypeBuilder.DefineMethod(
    'OpenProcess', #Method Name
    [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
    [intptr], #Method Return Type
    [Type[]] @(
        [ProcessAccessFlags], #ProcessAccess
        [bool],               #InheritHandle
        [int]                 #processID
    ) #Method Parameters
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
    [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
    [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
    [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
)
$FieldValueArray = [Object[]] @(
    'OpenProcess', 
    $True,
    $True,
    $True
)
$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('kernel32.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($CustomAttribute)
$PInvokeMethod = $TypeBuilder.DefineMethod(
    'OpenProcessToken', 
    [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
    [bool], #Method Return Type
    [Type[]] @(
        [intptr], 
        [int], 
        [intptr].MakeByRefType()
    ) #Method Parameters
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
    [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
    [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
)
$FieldValueArray = [Object[]] @(
    'OpenProcessToken',
    $True,
    $True
)
$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('advapi32.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
$PInvokeMethod = $TypeBuilder.DefineMethod(
    'GetTokenInformation', #Method Name
    [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
    [bool], #Method Return Type
    [Type[]] @(
        [intptr],                  #TokenHandle
        [TOKEN_INFORMATION_CLASS], #TokenInformationClass
        [intptr],                  #TokenInformation
        [uint32],                  #TokenInformationLength
        [uint32].MakeByRefType()   #ReturnLength
    ) #Method Parameters
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
    [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
    [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
    [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
)
$FieldValueArray = [Object[]] @(
    'GetTokenInformation',
    $True,
    $True,
    $True
)
$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('advapi32.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($CustomAttribute)
$PInvokeMethod = $TypeBuilder.DefineMethod(
    'LookupPrivilegeValue', #Method Name
    [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
    [bool], #Method Return Type
    [Type[]] @(
        [string],              #lpSystemName
        [string],              #lpName
        [long].MakeByRefType() #lpLuid
    ) #Method Parameters
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
    [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
    [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
)
$FieldValueArray = [Object[]] @(
    'LookupPrivilegeValue',
    $True
)
$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('advapi32.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
$PInvokeMethod = $TypeBuilder.DefineMethod(
    'LookupPrivilegeNameW', #Method Name
    [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
    [bool], #Method Return Type
    [Type[]] @(
        [intptr],
        [intptr],
        [intptr],
        [uint32].MakeByRefType()
    ) #Method Parameters
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
    [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
    [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
    [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
)
$FieldValueArray = [Object[]] @(
    'LookupPrivilegeNameW', #CASE SENSITIVE!!
    $True,
    $True,
    $True
)
$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('advapi32.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($CustomAttribute)
$PInvokeMethod = $TypeBuilder.DefineMethod(
    'CloseHandle',
    [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
    [bool], #Method Return Type
    [Type[]] @(
        [intptr] #Handle
    ) #Method Parameters
)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [Reflection.FieldInfo[]] @(
    [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
    [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling')
    [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig')
)
$FieldValueArray = [Object[]] @(
    'CloseHandle', #CASE SENSITIVE!!
    $True,
    $True,
    $True
)
$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
    $DllImportConstructor,
    @('kernel32.dll'),
    $FieldArray,
    $FieldValueArray
)
$PInvokeMethod.SetCustomAttribute($CustomAttribute)
[void]$TypeBuilder.CreateType()

# ----------------
# Non-powershell custom function
Function AddSignedIntAsUnsigned {
    ##Source function from Matt Graeber and Joe Balek
    [cmdletbinding()]
	Param(
	[Parameter(Position = 0, Mandatory = $true)]
	[Int64]
	$Value1,
		
	[Parameter(Position = 1, Mandatory = $true)]
	[Int64]
	$Value2
	)
		
	[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
	[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
	[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

	if ($Value1Bytes.Count -eq $Value2Bytes.Count)
	{
		$CarryOver = 0
		for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
		{
			#Add bytes
			[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

			$FinalBytes[$i] = $Sum -band 0x00FF
				
			if (($Sum -band 0xFF00) -eq 0x100)
			{
				$CarryOver = 1
			}
			else
			{
				$CarryOver = 0
			}
            Write-Verbose "Carryover: $($CarryOver)"
		}
	}
	else
	{
		Throw "Cannot add bytearrays of different sizes"
	}
		
	return [BitConverter]::ToInt64($FinalBytes, 0)
}
# ----------------------------------
# BEGIN CODE for "whoami /priv"
$PROCESS_QUERY_INFORMATION = [ProcessAccessFlags]::QueryInformation
$TOKEN_ALL_ACCESS = [System.Security.Principal.TokenAccessLevels]::AllAccess
$Process = Get-Process -Id $PID

$hProcess = [PoShPrivilege]::OpenProcess(
                $PROCESS_QUERY_INFORMATION, 
                $True, 
                $Process.Id
            )
            
$hProcessToken = [intptr]::Zero
[void][PoShPrivilege]::OpenProcessToken(
	$hProcess, 
	$TOKEN_ALL_ACCESS, 
	[ref]$hProcessToken
)

[void][PoShPrivilege]::CloseHandle($hProcess)

[UInt32]$TokenPrivSize = 1000
[IntPtr]$TokenPrivPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
[uint32]$ReturnLength = 0
[void][PoShPrivilege]::GetTokenInformation(
	$hProcessToken,
	[TOKEN_INFORMATION_CLASS]::TokenPrivileges,
	$TokenPrivPtr,
	$TokenPrivSize,
	[ref]$ReturnLength
)

$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivPtr, [Type][TOKEN_PRIVILEGES])
[IntPtr]$PrivilegesBasePtr = [IntPtr](AddSignedIntAsUnsigned $TokenPrivPtr ([System.Runtime.InteropServices.Marshal]::OffsetOf(
                [Type][TOKEN_PRIVILEGES], "Privileges"
            )))
$LuidAndAttributeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][LUID_AND_ATTRIBUTES])
for ($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
                $LuidAndAttributePtr = [IntPtr](AddSignedIntAsUnsigned $PrivilegesBasePtr ($LuidAndAttributeSize * $i))
                $LuidAndAttribute = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributePtr, [Type][LUID_AND_ATTRIBUTES])
                [UInt32]$PrivilegeNameSize = 60
                $PrivilegeNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PrivilegeNameSize)
                $PLuid = $LuidAndAttributePtr
                [void][PoShPrivilege]::LookupPrivilegeNameW(
                    [IntPtr]::Zero, 
                    $PLuid, 
                    $PrivilegeNamePtr, 
                    [Ref]$PrivilegeNameSize
                )
                $PrivilegeName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($PrivilegeNamePtr)
                $Enabled = $False
                If ($LuidAndAttribute.Attributes -ne 0) {
                    $Enabled = $True
                }
                $Object = [pscustomobject]@{
                    Computername = $env:COMPUTERNAME
                    Account = "{0}\{1}" -f ($env:USERDOMAIN, $env:USERNAME)
                    Privilege = $PrivilegeName
                    Enabled = $Enabled
                }
                $Object.pstypenames.insert(0,'PSPrivilege.CurrentUserPrivilege')
                $Object
            }

			
