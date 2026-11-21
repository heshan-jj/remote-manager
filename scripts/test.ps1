param(
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
dotnet test tests/HHJ.Core.Tests -c $Configuration
dotnet test tests/HHJ.Infrastructure.Tests -c $Configuration
dotnet test tests/HHJ.Setup.Tests -c $Configuration
