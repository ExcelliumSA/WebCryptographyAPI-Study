npm search --json crypto > repo.json
$repos = Get-Content repo.json | ConvertFrom-Json
$patterns = @("\.subtle\.", "CryptoKey", "window\.crypto")
Write-Host "References to Web Cryptography API found in code base?" -ForegroundColor Yellow
foreach ($repo in $repos) {
    if ($repo.links.repository -like "https*") {
        $repoName = $repo.name
        $repoUrl = $repo.links.repository
        Remove-Item -Recurse -Force WorkTempo -ErrorAction SilentlyContinue
        git clone -q $repoUrl WorkTempo
        $occurences = Get-ChildItem -Path .\WorkTempo\*.* -Recurse | Select-String -CaseSensitive -AllMatches -Pattern $patterns
        if ($occurences.Length -gt 0) {
            Write-Host "[X] $repoName" -ForegroundColor White
        }else{
            Write-Host "[ ] $repoName" -ForegroundColor White
        }
    }   
}
Remove-Item -Recurse -Force WorkTempo
Remove-Item -Force repo.json