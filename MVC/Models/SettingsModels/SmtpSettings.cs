using System;

namespace MVC.Models.SettingsModels
{
  /*public class Smtp
  {
    public Smtp(SmtpSettings config)
    {
      if (config == null) throw new ArgumentNullException(nameof(config));

      From = config.From;
      DisplayName = config.DisplayName;
      Host = config.Host;
      Port = config.Port;
      EnableSSL = config.EnableSSL;
      UserName = config.UserName;
      Password = config.Password;
    }

    public string From { get; set; }
    public string DisplayName { get; set; }
    public string Host { get; set; }
    public int Port { get; set; }
    public bool EnableSSL { get; set; }
    public string UserName { get; set; }
    public string Password { get; set; }
  }*/
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