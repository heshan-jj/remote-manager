using System.Windows;
using HHJ.Agent.Setup.ViewModels;

namespace HHJ.Agent.Setup;

public partial class MainWindow : Window
{
    public MainWindow(SetupWizardViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
