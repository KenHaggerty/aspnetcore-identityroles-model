namespace MVC.Models.SettingsModels
{
  public class Logging
  {
    public bool LogginOn { get; set; } = true;
    public bool CookiesOn { get; set; } = true;
    public bool EmailErrorsOn { get; set; } = true;
    private double _viewCookieMinutesTimeSpan = 0;
    public double ViewCookieMinutesTimeSpan
    {
      get
      {
        if (_viewCookieMinutesTimeSpan == 0)
        {
          _viewCookieMinutesTimeSpan = 60;
        }
        return _viewCookieMinutesTimeSpan;
      }
      set
      {
        _viewCookieMinutesTimeSpan = value;
      }
    }
  }

}