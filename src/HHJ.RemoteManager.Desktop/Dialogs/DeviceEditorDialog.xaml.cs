using System.Globalization;
using System.Windows;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Core.Security;

namespace HHJ.RemoteManager.Desktop.Dialogs;

public partial class DeviceEditorDialog : Window
{
    private readonly DeviceProfile _profile;

    public DeviceEditorDialog(DeviceProfile profile, IEnumerable<SshKeyInfo> keys)
    {
        InitializeComponent();
        _profile = profile.Clone();

        var keyList = keys.ToList();
        KeyCombo.ItemsSource = keyList;

        DisplayNameBox.Text = _profile.DisplayName;
        AddressBox.Text = _profile.Address;
        PortBox.Text = _profile.Port.ToString(CultureInfo.InvariantCulture);
        UsernameBox.Text = _profile.Username;
        TagsBox.Text = string.Join(", ", _profile.Tags);
        KeyCombo.SelectedItem = keyList.FirstOrDefault(k => k.Id == _profile.KeyId) ?? keyList.FirstOrDefault();
    }

    public DeviceProfile ResultProfile => _profile;

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(PortBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
        {
            ErrorText.Text = "SSH port must be a valid integer (1-65535).";
            return;
        }

        _profile.DisplayName = DisplayNameBox.Text.Trim();
        _profile.Address = AddressBox.Text.Trim();
        _profile.Port = port;
        _profile.Username = UsernameBox.Text.Trim();
        _profile.KeyId = (KeyCombo.SelectedItem as SshKeyInfo)?.Id;
        _profile.Tags = DeviceProfileValidator.ParseTags(TagsBox.Text);

        var validation = DeviceProfileValidator.Validate(_profile);
        if (!validation.IsValid)
        {
            ErrorText.Text = string.Join("\n", validation.Errors);
            return;
        }

        DialogResult = true;
    }
}
