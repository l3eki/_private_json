<#
  interface_collection.json 瑙ｅ瘑鑴氭湰
  鐢ㄦ硶:
    pwsh -File .\aes_decrypt.ps1 -In .\interface_collection.json -Out .\鎺ュ彛娴嬭瘯.postman_collection.json -Key 123456
#>
param(
  [string]$In  = "E:\deepseek-workspace\interface_collection.json",
  [string]$Out = "E:\deepseek-workspace\鎺ュ彛娴嬭瘯.postman_collection.json",
  [string]$Key = "123456"
)

$ErrorActionPreference = 'Stop'
$envl = Get-Content -LiteralPath $In -Raw | ConvertFrom-Json

$sha = [System.Security.Cryptography.SHA256]::Create()
$keyBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.Key     = $keyBytes
$mode = $envl.alg
$aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$aes.IV      = [Convert]::FromBase64String($envl.iv)

$dec = $aes.CreateDecryptor()
$cipher = [Convert]::FromBase64String($envl.ciphertext)
$plain = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
$dec.Dispose(); $aes.Dispose()

$actual = [Convert]::ToBase64String($sha.ComputeHash($plain))
if ($actual -ne $envl.plainSha256) {
  throw "SHA-256 mismatch: key wrong or file corrupted ($actual vs $($envl.plainSha256))"
}

[System.IO.File]::WriteAllBytes($Out, $plain)
Write-Host "OK -> $Out  ($($plain.Length) bytes, sha256 verified)"

