using System;

namespace MVC.Models.SettingsModels
{
  public class SmtpSettings
  {
    public string From { get; set; }
    public string DisplayName { get; set; }
    public string Host { get; set; }
    public int Port { get; set; }
    public bool EnableSSL { get; set; }
    public string UserName { get; set; }
    public string Password { get; set; }
  }
}