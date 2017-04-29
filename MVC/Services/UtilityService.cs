using MVC.Data;
using MVC.Models;
using MVC.Models.SettingsModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using System;
using System.Text;

using System.Threading.Tasks;

namespace MVC.Services
{
  public class UtilityService : IUtilityService
  {
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;
    private readonly Settings _settings;
    public UtilityService(
    IEmailSender emailSender,
    ISmsSender smsSender,
    IOptionsSnapshot<Settings> settings)
    {
      _emailSender = emailSender;
      _smsSender = smsSender;
      _settings = settings.Value;
    }

    public async void SendEmailSimpleTest()
    {
      var sb = new StringBuilder("<html><body>");
      sb.Append("<div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>Email Simple Test</div>");
      sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
      sb.Append("<br/>Test from Utilities.<br/><br/> If you have any problem, please let me know.<br/>");
      sb.Append("Email  <a href='mailto:");

      sb.Append("ADMIN@DOMAIN.COM");

      sb.Append("?subject=Email Simple Test'>Administrator</a>");
      sb.Append("<br/><br/>Thank you,<br/>Administrator<br/><br/>");
      sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

      //await _emailSender.SendEmailAsync("ADMIN@DOMAIN.COM", "Email Simple Test", sb.ToString());
      await Task.Run(() => { Task.Delay(500); });

    }

    public async void SendEmailSettingsTest()
    {
      var sb = new StringBuilder("<html><body>");
      sb.Append("<div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>Email Settings Test for " + _settings.Name);
      sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
      sb.Append("<br/>Test from " + _settings.Name + ".<br/><br/> If you have any problem, please let me know.<br/>");
      sb.Append("Email  <a href='mailto:" + _settings.SupportEmail + "?subject=Email Settings Test'>" + _settings.SupportName + "</a>");
      sb.Append("<br/><br/>Thank you,<br/>" + _settings.SupportName + "<br/><br/>");
      sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

      //await _emailSender.SendEmailAsync(_settings.SupportEmail, "Email Settings Test", sb.ToString());
      await Task.Run(() => { Task.Delay(500); });

    }


    public void SetViewCookie(HttpContext context, string subject, string name, LogType type = LogType.Information, bool sendemail = false)
    {
      if (_settings.Logging.CookiesOn)
      {
        HttpRequest curRequest = context.Request;
        if (curRequest.Cookies != null && curRequest.Cookies.Count > 0)
        {

          if (curRequest.Cookies[name] == null)
          {
            CookieOptions options = new CookieOptions();
            var ex = DateTime.Now.AddMinutes(_settings.Logging.ViewCookieMinutesTimeSpan);
            options.Expires = ex;
            context.Response.Cookies.Append(name, ex.ToString(), options);
            if (name == "HomeView")
            {
              type = LogType.Information;
            }
            InsertLogEntry(context, subject, $"Added new { name } cookie.", type, sendemail);
          }
        }
        else
        {
          // Bots do not have a HttpRequest
          InsertLogEntry(context, subject, $"Unable to set { name } cookie.", type, sendemail);
        }
      }
    }
    public void DeleteViewCookie(HttpContext context, string subject, string name, LogType type = LogType.Information, bool sendemail = false)
    {
      HttpRequest curRequest = context.Request;
      if (curRequest.Cookies != null && curRequest.Cookies.Count > 0)
      {
        if (curRequest.Cookies[name] != null)
        {
          CookieOptions options = new CookieOptions()
          {
            Expires = DateTime.Now.AddDays(-1d)
          };
          context.Response.Cookies.Append(name, "delete", options);
          InsertLogEntry(context, subject, $"Deleted { name } cookie.", type, sendemail);
        }
      }
    }

    public async void InsertLogEntry(HttpContext context, string subject, string message, LogType type = LogType.Information, bool sendemail = false,
        Exception e = null, string controller = "", string action = "")
    {
      if (_settings.Logging.LogginOn)
      {
        controller = (controller.Length > 0 ? controller : context.GetRouteValue("controller").ToString());
        action = (action.Length > 0 ? action : context.GetRouteValue("action").ToString());

        var host = _settings.Host;
        var userName = (context.User.Identity.Name != null && context.User.Identity.Name.Length > 0 ? context.User.Identity.Name : "Unknown");

        var exceptionString = string.Empty;
        if (e == null)
        {
          exceptionString = "Exception: NONE";
        }
        else
        {
          exceptionString = e.ToString();
        }

        var le = new LogEntry(subject, message, userName, controller, action, host, exceptionString, type);
        using (var db = new LogDbContext())
        {
          await db.LogEntries.AddAsync(le);
          try
          {
            await db.SaveChangesAsync();
          }
          catch (Exception ex)
          {
            exceptionString = ex.ToString();
            SendSupportNotifyEmail(_settings.SupportEmail, "Exception LogDbContext", "SaveChangesAsync threw an exception. Check the SQLite file integrity.",
                controller, action, userName, exceptionString, LogType.Critical, "Not Logged");
            sendemail = false;
          }
        }
        if (sendemail && _settings.Logging.EmailErrorsOn)
        {
          SendSupportNotifyEmail(_settings.SupportEmail, subject, message, controller, action, userName, exceptionString, type, le.ID);
        }
      }
    }

    public async void SendSupportNotifyEmail(string email, string subject, string message, string controller, string action, string userName,
        string exceptionString = "", LogType type = LogType.Information, string logid = "")
    {
      var stype = Enum.GetName(typeof(LogType), type);
      var sb = new StringBuilder(stype + "/" + subject +
          "\nDate/Time\t= " + DateTime.UtcNow.ToLocalTime().ToString("yyyy-MM-dd|hh:mm tt") +
          "\nMessage\t= " + message +
          "\nUserName\t= " + userName + "\t\tController\t= " + controller + "\t\tAction\t= " + action +
          "\nLogID\t\t= " + logid.ToString() +
          "\n\nException\t= " + exceptionString + "\n");

      //await _emailSender.SendEmailAsync(email, stype + "/" + subject, sb.ToString(), true);
      await Task.Run(() => { Task.Delay(500); });
    }
  }
}
