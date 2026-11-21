using System.Text;
using HHJ.RemoteManager.Core.Connections;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Core.Remote;
using HHJ.RemoteManager.Core.Ssh;
using Xunit;

namespace HHJ.Core.Tests;

public sealed class ConnectionStateMachineAndSecurityTests
{
    [Fact]
    public void StateMachine_EnforcesValidTransitionsAndAlwaysAllowsDisconnect()
    {
        var sm = new ConnectionStateMachine();
        Assert.Equal(ConnectionState.Disconnected, sm.State);

        Assert.False(sm.TryTransition(ConnectionState.Connected)); // cannot jump straight to Connected
        Assert.True(sm.TryTransition(ConnectionState.Connecting));
        Assert.True(sm.TryTransition(ConnectionState.Connected));
        Assert.True(sm.TryTransition(ConnectionState.Disconnected));

        Assert.True(sm.TryTransition(ConnectionState.Connecting));
        Assert.True(sm.Fail(new ConnectionFailure(FailureKind.AuthenticationFailed, "bad key")));
        Assert.Equal(ConnectionState.AuthenticationFailed, sm.State);
        Assert.True(sm.TryTransition(ConnectionState.Disconnected));
    }

    [Fact]
    public void DeviceProfileValidator_RejectsInvalidInputsAndAcceptsValidProfile()
    {
        var valid = new DeviceProfile
        {
            DisplayName = "Brother-PC (Sri Lanka)",
            Address = "brother-pc.tail1234.ts.net",
            Port = 22,
            Username = "heshan",
            KeyId = "key1",
            Tags = ["family", "win11"],
        };
        Assert.True(DeviceProfileValidator.Validate(valid).IsValid);

        var invalid = new DeviceProfile
        {
            DisplayName = "Bad;Name",
            Address = "bad host!",
            Port = 70000,
            Username = "bad/user",
            KeyId = null,
        };
        var res = DeviceProfileValidator.Validate(invalid);
        Assert.False(res.IsValid);
        Assert.True(res.Errors.Count >= 4);
    }

    [Fact]
    public void PowerShellCommand_EncodesUtf16LeAndEscapesQuotes()
    {
        var cmd = PowerShellCommand.Build("Get-Process");
        Assert.StartsWith("powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ", cmd);
        var b64 = cmd.Split(' ')[^1];
        var decoded = Encoding.Unicode.GetString(Convert.FromBase64String(b64));
        Assert.Equal("Get-Process\n", decoded);

        Assert.Equal("'a''b\u2019\u2019c'", PowerShellCommand.Literal("a'b\u2019c"));
        Assert.False(PowerShellCommand.IsValidServiceName("sshd; calc.exe"));
        Assert.True(PowerShellCommand.IsValidServiceName("sshd"));
    }

    [Fact]
    public async Task RemoteEndpointClient_ThrowsAccessDeniedWhenScriptReportsDenied()
    {
        var session = new FakeSshSession("{\"ok\":false,\"denied\":true,\"error\":\"Access is denied.\"}");
        var client = new RemoteEndpointClient(session);

        await Assert.ThrowsAsync<RemoteAccessDeniedException>(() =>
            client.ControlServiceAsync("sshd", RemoteScripts.ServiceAction.Stop, CancellationToken.None));
    }

    private sealed class FakeSshSession(string stdout) : ISshSession
    {
        public bool IsConnected => true;
        public HostKeyInfo HostKey { get; } = new("ssh-ed25519", "abc");
        public string ServerVersion => "SSH-2.0-OpenSSH";
#pragma warning disable CS0067
        public event EventHandler<Exception?>? Disconnected;
#pragma warning restore CS0067

        public Task<SshCommandResult> RunAsync(string commandText, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new SshCommandResult(0, stdout, "", TimeSpan.FromMilliseconds(12)));

        public Task<IShellChannel> OpenShellAsync(int columns, int rows, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
