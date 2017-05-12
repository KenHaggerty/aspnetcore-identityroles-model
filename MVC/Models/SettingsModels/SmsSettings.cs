using System;

namespace MVC.Models.SettingsModels
{
  public class SmsSettings
  {
    
      public string Sid { get; set; }
      public string Token { get; set; }
      public string BaseUri { get; set; }
      public string RequestUri { get; set; }
      public string From { get; set; }
  } 
}