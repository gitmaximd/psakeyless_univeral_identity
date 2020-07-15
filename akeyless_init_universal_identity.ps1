Param(
    # Parameter help description
    [Parameter(Mandatory = $true)]
    [string]
    $AccessID,

    # Parameter help description
    [Parameter(Mandatory = $true)]
    [securestring]
    $AccessKey = (Read-Host -Prompt "Access Key" -AsSecureString)
)


$proxy_url       = "https://rest.akeyless-security.com/"
$sched_task_name = "akeyless_universal_identity_rotator"
$token_file      = "$HOME/.vault-token"

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

$body = @{
    cmd          = 'configure'
    'access-id'  = $AccessID
    'access-key' = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessKey))
}

$token = (Invoke-RestMethod -Method Post -Uri $proxy_url -Body $body -ContentType 'application/x-www-form-urlencoded').token
$headers.Clear()
Write-Host "Starter token received [$token]"

if([string]::IsNullOrEmpty($token)) {
    Write-Host "Error! empty token"
} else {
    $token | Out-File $token_file
    $script_name = "akeyless_universal_identity_token_rotator.ps1"
    $task_to_run = "powershell -noninteractive -File $([System.IO.Path]::Combine($PSScriptRoot, $script_name))"

    try {
        Get-ScheduledTask -TaskName $sched_task_name -ErrorAction Stop
        schtasks /delete /tn $sched_task_name /f # TODO: Replace with PS native
    }
    catch {
        schtasks /create /sc MINUTE /tn $sched_task_name /tr $task_to_run /ru "SYSTEM" /mo 1 # TODO: Replace with PS native
    }   
    Write-Host "AKEYLESS Universal Identity successfully initiated"
}

