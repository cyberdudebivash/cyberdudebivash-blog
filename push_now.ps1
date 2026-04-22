$git = "C:\Program Files\Git\cmd\git.exe"
$repo = "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
Set-Location $repo
& $git push origin main 2>&1 | Tee-Object -FilePath "$repo\push_v6_out.txt"
Write-Output "EXIT: $LASTEXITCODE" | Add-Content "$repo\push_v6_out.txt"
