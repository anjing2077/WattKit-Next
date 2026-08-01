using BD.WTTS.UI.ViewModels;

namespace BD.WTTS.UI.Views.Pages;

public partial class DnsSecurityStatusControl : ReactiveUserControl<DnsSecurityStatusViewModel>
{
    public DnsSecurityStatusControl()
    {
        InitializeComponent();
    }

    void ResetButton_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        ViewModel?.Reset();
    }
}
