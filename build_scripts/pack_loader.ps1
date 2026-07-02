param(
    [string]$OutHeader = "C:\Users\K\Desktop\PenisFinger\betest_legacy\source\embedded_data.h"
)

$ErrorActionPreference = "Stop"

# Key seed parts - scattered so not a single searchable string
$seedParts = @("Pn!sF", "1ng3r", "_v188", "_Krn#", "L0ad+")
$seed = $seedParts -join ""
$sha = [System.Security.Cryptography.SHA256]::Create()
$aesKey = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
Write-Host "AES-256 key derived ($($aesKey.Length) bytes)"

# Files to embed
$files = [ordered]@{
    "mapper"   = "C:\Users\K\Desktop\PenisFinger\run\mapper_nal.exe"
    "driver"   = "C:\Users\K\Desktop\PenisFinger\vm\vm_transfer\BetestD.sys"
    "byovd"    = "C:\Users\K\Desktop\PenisFinger\build\TRIXX.sys"
    "injector" = "C:\Users\K\Desktop\PenisFinger\build\injector.exe"
    "unt_ext"  = "C:\Users\K\Desktop\PenisFinger\build\externaltest.exe"
    "unt_int"  = "C:\Users\K\Desktop\PenisFinger\build\unturned_internal.dll"
}

if (-not (Test-Path $files["byovd"])) {
    $files["byovd"] = "C:\Users\K\Desktop\PenisFinger\vm\vm_transfer\TRIXX.sys"
}

$imageNames = @("fortnite","valorant","apex","rust","tarkov","pubg","cod","r6s","dayz","unturned")
foreach ($n in $imageNames) {
    $p = "C:\Users\K\Desktop\PenisFinger\run\images\$n.jpg"
    if (Test-Path $p) { $files["img_$n"] = $p }
}

function Encrypt-FileData($path) {
    $data = [System.IO.File]::ReadAllBytes($path)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $aesKey
    $aes.GenerateIV()
    $enc = $aes.CreateEncryptor()
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $enc, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($data, 0, $data.Length)
    $cs.FlushFinalBlock()
    $encrypted = $ms.ToArray()
    $cs.Close()
    $ms.Close()
    return @{ IV = $aes.IV; Data = $encrypted; OrigSize = $data.Length }
}

function Format-Bytes($bytes, $varName) {
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("static const unsigned char ${varName}[] = {")
    $lineBytes = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        [void]$lineBytes.Add(("0x{0:X2}" -f $bytes[$i]))
        if ($lineBytes.Count -ge 20 -or $i -eq $bytes.Length - 1) {
            $comma = ""
            if ($i -lt $bytes.Length - 1) { $comma = "," }
            [void]$lines.Add("    " + ($lineBytes -join ",") + $comma)
            $lineBytes.Clear()
        }
    }
    [void]$lines.Add("};")
    return $lines -join "`r`n"
}

# Build header
$out = New-Object System.Collections.ArrayList
[void]$out.Add("// Auto-generated - DO NOT EDIT")
[void]$out.Add("#pragma once")
[void]$out.Add("")

# Key seed parts as byte arrays
for ($i = 0; $i -lt $seedParts.Count; $i++) {
    $b = [System.Text.Encoding]::UTF8.GetBytes($seedParts[$i])
    $h = ($b | ForEach-Object { "0x{0:X2}" -f $_ }) -join ","
    [void]$out.Add("static const unsigned char g_ks${i}[] = { $h };")
}
[void]$out.Add("static const int g_ksCount = $($seedParts.Count);")
$ptrs = (0..($seedParts.Count-1) | ForEach-Object { "g_ks$_" }) -join ", "
[void]$out.Add("static const unsigned char* g_ksParts[] = { $ptrs };")
$lens = ($seedParts | ForEach-Object { $_.Length.ToString() }) -join ", "
[void]$out.Add("static const int g_ksLens[] = { $lens };")
[void]$out.Add("")

# Encrypt each file
$entries = @()
$idx = 0
foreach ($kv in $files.GetEnumerator()) {
    $id = $kv.Key
    $fpath = $kv.Value
    if (-not (Test-Path $fpath)) {
        Write-Host "SKIP: $fpath"
        continue
    }
    $sz = (Get-Item $fpath).Length
    Write-Host "Encrypting: $id ($sz bytes)"
    $enc = Encrypt-FileData $fpath

    $ivHex = ($enc.IV | ForEach-Object { "0x{0:X2}" -f $_ }) -join ","
    [void]$out.Add("static const unsigned char g_iv${idx}[] = { $ivHex };")
    [void]$out.Add((Format-Bytes $enc.Data "g_enc${idx}"))
    [void]$out.Add("")

    $entries += [PSCustomObject]@{ Id=$id; Idx=$idx; EncSize=$enc.Data.Length; OrigSize=$enc.OrigSize }
    $idx++
}

# Entry table
[void]$out.Add("struct EmbeddedEntry {")
[void]$out.Add("    const char* id;")
[void]$out.Add("    const unsigned char* iv;")
[void]$out.Add("    const unsigned char* data;")
[void]$out.Add("    unsigned int encSize;")
[void]$out.Add("    unsigned int origSize;")
[void]$out.Add("};")
[void]$out.Add("")
[void]$out.Add("static const EmbeddedEntry g_embedded[] = {")
foreach ($e in $entries) {
    [void]$out.Add("    { `"$($e.Id)`", g_iv$($e.Idx), g_enc$($e.Idx), sizeof(g_enc$($e.Idx)), $($e.OrigSize) },")
}
[void]$out.Add("};")
[void]$out.Add("static const int g_embeddedCount = sizeof(g_embedded) / sizeof(g_embedded[0]);")

$text = $out -join "`r`n"
[System.IO.File]::WriteAllText($OutHeader, $text, [System.Text.UTF8Encoding]::new($false))
$hsz = (Get-Item $OutHeader).Length
Write-Host "Generated: $OutHeader ($hsz bytes, $($entries.Count) entries)"
