using System;

namespace MVC.Models.SettingsModels
{
  /*public class Sms
    {
        public Sms(SmsSettings config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Sid = config.Sid;
            Token = config.Token;
            BaseUri = config.BaseUri;
            RequestUri = config.RequestUri;
            From = config.From;
        }
        public string Sid { get; protected set; }
        public string Token { get; protected set; }
        public string BaseUri { get; protected set; }
        public string RequestUri { get; protected set; }
        public string From { get; protected set; }
    }*/
  public class SmsSettings
  {
    
      public string Sid { get; set; }
      public string Token { get; set; }
      public string BaseUri { get; set; }
      public string RequestUri { get; set; }
      public string From { get; set; }
  } 
}