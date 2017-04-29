namespace MVC.Models.SettingsModels
{
  public class Settings
  {
    public string Name { get; set; }
    public string Host { get; set; }
    public string Protocol { get; set; }
    public bool RequireSSL { get; set; }
    public string Copyright { get; set; }
    public string SupportName { get; set; }
    public string SupportURL { get; set; }
    public string SupportEmail { get; set; }
    public Logging Logging { get; set; }
    public SmtpSettings SmtpSettings { get; set; }
    public SmsSettings SmsSettings { get; set; }
  }

}