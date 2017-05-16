using MVC.Models;
using Microsoft.AspNetCore.Http;
using System;

namespace MVC.Services
{
    public interface IUtilityService
    {
        void SendEmailSettingsTest();
        void SendEmailSimpleTest();
        void DeleteViewCookie(HttpContext context, string subject, string name, LogType type = LogType.Information,
          bool sendemail = false);
        void SetViewCookie(HttpContext context, string subject, string name, LogType type = LogType.Information,
          bool sendemail = false);
        void InsertLogEntry(HttpContext context, string subject, string message, LogType type = LogType.Information,
          bool sendemail = false,
            Exception e = null, string controller = "", string action = "");
        void SendSupportNotifyEmail(string email, string subject, string message, string controller, string action, string username,
            string exceptionString = "", LogType type = LogType.Information, string logid = "");
    }
}