param(
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
dotnet build HHJ.RemoteManager.sln -c $Configuration
