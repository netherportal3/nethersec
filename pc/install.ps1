<#
.SYNOPSIS
  Installs the nethersec PC scanner for the current Windows user.

.DESCRIPTION
  Copies the scanner into %USERPROFILE%\.nethersec-pc, limits that folder to your
  Windows account, creates config.json and watch.json from the examples when they
  are missing, and registers a scheduled task that runs every 6 hours and 5 minutes
  after logon.

  The key (hub) or the webhook URL (webhook) is kept in secret.dpapi, encrypted with
  Windows DPAPI for your account, never in config.json. Other accounts, backups and
  copies of the disk cannot decrypt it; programs running as you can. A key or URL
  that an older version left in config.json is moved into secret.dpapi by the next
  scan that is not a dry run.

  The folder is in your profile, not in AppData: a packaged (MSIX) app can have its
  AppData writes redirected to a private copy, and the scheduled task would not see
  files written that way. A plain folder in your profile avoids that.

  The task runs as you, not elevated, only while you are logged on, and starts late
  if the PC was asleep at the planned time. It launches node through
  "conhost.exe --headless", so no console window flashes. It stops after 20 minutes.

  Safe to run again: it updates the scripts and the task, and keeps your config,
  watch list, state, key and webhook URL.

.PARAMETER NewKey
  Make a new key for the hub, save it encrypted in secret.dpapi, set delivery "hub" in
  config.json, and print the line to add to the hub's keys file. The key itself is
  never printed. Replaces any older key or webhook URL: remove the old line from the
  hub.

.PARAMETER HubUrl
  With -NewKey: the hub's address, for example https://hub.example.com. Saved in
  config.json.

.PARAMETER DiscordUserId
  With -NewKey: your Discord user ID, for the dm= part of the printed line. The hub
  then sends this PC's reports to you as direct messages.

.PARAMETER Webhook
  Send reports straight to a Discord webhook instead of a hub. Asks for the webhook
  URL (it does not show while you paste it), saves it encrypted in secret.dpapi, and
  sets delivery "webhook" in config.json. Replaces any older key or webhook URL.

.PARAMETER Uninstall
  Remove the scheduled task. The folder stays, with your key or webhook URL in
  secret.dpapi; delete it yourself if you no longer need it.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -WhatIf
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -NewKey -HubUrl https://hub.example.com -DiscordUserId 123456789012345678
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Webhook
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$NewKey,
  [string]$HubUrl,
  [string]$DiscordUserId,
  [switch]$Webhook,
  [switch]$Uninstall,
  [string]$TaskName = 'nethersec-pc-security-report'
)

$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:USERPROFILE '.nethersec-pc'
$files = @('pc-security-report.mjs', 'pc-security-run.mjs', 'pc-security-lib.mjs', 'config.example.json', 'watch.example.json', 'README.md')
$user = "$env:USERDOMAIN\$env:USERNAME"

# Give only the current account access to a folder (and, through inheritance, to
# every file made in it later) or to one file. No other user, and no group such as
# Administrators, keeps an entry. The owner is not changed.
function Set-OwnerOnlyAccess([string]$Path) {
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $full = [Security.AccessControl.FileSystemRights]::FullControl
  $allow = [Security.AccessControl.AccessControlType]::Allow
  if (Test-Path -LiteralPath $Path -PathType Container) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $full, $inherit, [Security.AccessControl.PropagationFlags]::None, $allow)
  } else {
    $acl = New-Object Security.AccessControl.FileSecurity
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $full, $allow)
  }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

# True when every access entry on the path is for the current account.
function Test-OwnerOnlyAccess([string]$Path) {
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $rules = (Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  if ($rules.Count -eq 0) { return $false }
  foreach ($r in $rules) {
    if ($r.IdentityReference.Value -ne $sid) { return $false }
  }
  return $true
}

if ($Uninstall) {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $task) {
    Write-Host "No scheduled task named $TaskName."
  } elseif ($PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed the scheduled task $TaskName."
  }
  if (Test-Path -LiteralPath $dest) {
    Write-Host "The folder $dest is still there, with your key or webhook URL in secret.dpapi. Delete it if you no longer need it."
  }
  Write-Host 'Also remove this PC''s line from the hub''s keys file, or delete the webhook in Discord.'
  return
}

if ($NewKey -and $Webhook) { throw 'Use -NewKey (hub) or -Webhook (Discord webhook), not both.' }
if (-not $NewKey -and ($HubUrl -or $DiscordUserId)) { throw '-HubUrl and -DiscordUserId go with -NewKey.' }
if ($DiscordUserId -and $DiscordUserId -notmatch '^\d{17,20}$') { throw '-DiscordUserId takes your Discord user ID (17 to 20 digits).' }

$principalNow = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principalNow.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Warning 'This window is elevated. The task still runs as you without elevation, but a normal PowerShell window is better.'
}

$node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $node) { throw 'node.exe is not on PATH. Install Node.js first.' }
$conhost = Join-Path $env:WINDIR 'System32\conhost.exe'
if (-not (Test-Path -LiteralPath $conhost)) { throw "Missing $conhost." }
$script = Join-Path $dest 'pc-security-report.mjs'

# 1. The folder, limited to your account before any key or URL is written in it.
if (-not (Test-Path -LiteralPath $dest)) {
  if ($PSCmdlet.ShouldProcess($dest, 'Create folder')) { New-Item -ItemType Directory -Path $dest | Out-Null }
}
if ((Test-Path -LiteralPath $dest) -and $PSCmdlet.ShouldProcess($dest, 'Limit access to your Windows account only')) {
  Set-OwnerOnlyAccess $dest
}

# 2. Copy the scanner.
foreach ($f in $files) {
  $src = Join-Path $PSScriptRoot $f
  if (-not (Test-Path -LiteralPath $src)) { throw "Missing $src. Run this from the pc folder of the nethersec repo." }
  if ($PSCmdlet.ShouldProcess((Join-Path $dest $f), 'Copy scanner file')) {
    Copy-Item -LiteralPath $src -Destination (Join-Path $dest $f) -Force
  }
}

# 3. Config and watch list from the examples, only when missing.
foreach ($pair in @(@('config.example.json', 'config.json'), @('watch.example.json', 'watch.json'))) {
  $target = Join-Path $dest $pair[1]
  if (Test-Path -LiteralPath $target) {
    Write-Host "Keeping your $($pair[1])."
  } elseif ($PSCmdlet.ShouldProcess($target, "Create from $($pair[0])")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $pair[0]) -Destination $target
    Write-Host "Created $($pair[1]) from $($pair[0])."
  }
}
$cfgPath = Join-Path $dest 'config.json'
if ((Test-Path -LiteralPath $cfgPath) -and $PSCmdlet.ShouldProcess($cfgPath, 'Limit access to your Windows account only')) {
  Set-OwnerOnlyAccess $cfgPath
  if (-not (Test-OwnerOnlyAccess $cfgPath)) {
    Write-Warning "Could not limit $cfgPath to your account. Other accounts on this PC may be able to read it."
  }
}

# 4. The key (with -NewKey) or the webhook URL (with -Webhook), saved encrypted for your
#    account in secret.dpapi. Neither ever goes on a command line: node makes the key
#    itself, the URL goes in on stdin, and node hands either one to Windows PowerShell's
#    DPAPI on stdin.
$secretPath = Join-Path $dest 'secret.dpapi'
if ($NewKey -and $PSCmdlet.ShouldProcess($secretPath, 'Save a new hub key, encrypted for your account (replaces any older key or webhook URL)')) {
  $nodeArgs = @($script, '--new-key', '--dir', $dest)
  if ($HubUrl) { $nodeArgs += @('--hub-url', $HubUrl) }
  if ($DiscordUserId) { $nodeArgs += @('--dm', $DiscordUserId) }
  & $node @nodeArgs
  if ($LASTEXITCODE -ne 0) { throw 'The key was not saved.' }
}
if ($Webhook -and $PSCmdlet.ShouldProcess($secretPath, 'Save a Discord webhook URL, encrypted for your account (replaces any older key or webhook URL)')) {
  Write-Host 'In Discord: channel settings > Integrations > Webhooks > New Webhook > Copy Webhook URL.'
  $secure = Read-Host -AsSecureString -Prompt 'Paste the webhook URL (it does not show) and press Enter'
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  $plain | & $node $script '--set-webhook' '--dir' $dest
  $code = $LASTEXITCODE
  $plain = $null
  if ($code -ne 0) { throw 'The webhook URL was not saved.' }
}
# The file inherits the folder's single entry; set it on the file too, as for config.json.
if (($NewKey -or $Webhook) -and (Test-Path -LiteralPath $secretPath) -and $PSCmdlet.ShouldProcess($secretPath, 'Limit access to your Windows account only')) {
  Set-OwnerOnlyAccess $secretPath
  if (-not (Test-OwnerOnlyAccess $secretPath)) {
    Write-Warning "Could not limit $secretPath to your account. It stays encrypted for your account."
  }
}

# 5. Scheduled task: every 6 hours from a start time picked at random on each install, with up
#    to 30 minutes of random delay, and 5 minutes after you log on. The scan times then differ
#    from one PC to the next and from day to day.
$action = New-ScheduledTaskAction -Execute $conhost -Argument "--headless `"$node`" `"$script`"" -WorkingDirectory $dest
$start = (Get-Date).Date.AddMinutes((Get-Random -Minimum 0 -Maximum 360))
$every6h = New-ScheduledTaskTrigger -Daily -At $start -RandomDelay (New-TimeSpan -Minutes 30)
$every6h.Repetition = (New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 1)).Repetition
$atLogon = New-ScheduledTaskTrigger -AtLogOn -User $user
$atLogon.Delay = 'PT5M'
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task (every 6 hours and at logon)')) {
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($every6h, $atLogon) -Settings $settings `
    -Principal $principal -Description 'nethersec PC security scanner. Reports problems to your nethersec hub or a Discord webhook.' -Force | Out-Null
  Write-Host "Scheduled task $TaskName is set: every 6 hours and 5 minutes after logon."
}

# 6. Say whether reports can go out yet. Only whether a key or URL exists is checked;
#    nothing is decrypted or shown here (a dry run of the scanner decrypts it).
if (Test-Path -LiteralPath $cfgPath) {
  $ready = $false
  $plainInUse = $false
  $plainUnused = $false
  try {
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
    if ($cfg.delivery -eq 'webhook') {
      $plainInUse = [bool]$cfg.webhookUrl
      $plainUnused = [bool]$cfg.key
      $ready = $plainInUse -or (Test-Path -LiteralPath $secretPath)
    } else {
      $plainInUse = [bool]$cfg.key
      $plainUnused = [bool]$cfg.webhookUrl
      $ready = ($plainInUse -or (Test-Path -LiteralPath $secretPath)) -and [bool]$cfg.hubUrl
    }
    $cfg = $null
  } catch {}
  if ($plainInUse) {
    Write-Host 'config.json still holds your key or webhook URL in plain text from an older version. The next scan that is not a dry run moves it into secret.dpapi, encrypted for your account. To move it now, run the scanner once without --dry-run:'
    Write-Host "  node `"$script`""
  } elseif ($plainUnused) {
    Write-Host 'config.json holds a key or webhook URL in plain text that your delivery mode does not use. Delete it from config.json.'
  }
  if (-not $ready) {
    Write-Host 'Nothing is sent yet. Run this again with -NewKey -HubUrl <hub address> (hub), or with -Webhook (Discord webhook).'
  }
}
Write-Host "Try it now: node `"$script`" --dry-run"
