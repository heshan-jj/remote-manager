param(
    [string]$Configuration = "Release",
    [string]$OutputRoot = "artifacts/publish"
)
$ErrorActionPreference = "Stop"

dotnet publish src/HHJ.Agent.Setup/HHJ.Agent.Setup.csproj `
    -c $Configuration `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -o "$OutputRoot/agent-setup"

dotnet publish src/HHJ.RemoteManager.Desktop/HHJ.RemoteManager.Desktop.csproj `
    -c $Configuration `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -o "$OutputRoot/desktop"

Write-Host "Published artifacts under $OutputRoot"
