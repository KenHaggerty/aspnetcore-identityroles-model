using MVC.Models;
using MVC.Models.SettingsModels;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace MVC.Services
{
  // This class is used by the application to send Email and SMS
  // when you turn on two-factor authentication in ASP.NET Identity.
  // For more details see this link https://go.microsoft.com/fwlink/?LinkID=532713
  public class AuthMessageSender : IEmailSender, ISmsSender
  {
    private readonly Settings _settings;
    public AuthMessageSender(
        IOptionsSnapshot<Settings> settings)
    {
      _settings = settings.Value;
    }
    public async Task SendEmailAsync(string email, string subject, string message)
    {
      // Plug in your email service here to send an email.
      //return Task.FromResult(0);
      var emailMessage = new MimeMessage();
      emailMessage.From.Add(new MailboxAddress(_settings.SmtpSettings.DisplayName, _settings.SmtpSettings.From));
      emailMessage.To.Add(new MailboxAddress("", email));
      emailMessage.Subject = subject;
      var bodyBuilder = new BodyBuilder();
      bodyBuilder.HtmlBody = message;
      emailMessage.Body = bodyBuilder.ToMessageBody();
      //emailMessage.Body = new TextPart("plain") { Text = message };                       
      using (var client = new SmtpClient())
      {
        client.AuthenticationMechanisms.Remove("XOAUTH2");
        await client.ConnectAsync(_settings.SmtpSettings.Host, _settings.SmtpSettings.Port, SecureSocketOptions.None)
          .ConfigureAwait(false);
        await client.AuthenticateAsync(_settings.SmtpSettings.UserName, _settings.SmtpSettings.Password);
        await client.SendAsync(emailMessage).ConfigureAwait(false);
        await client.DisconnectAsync(true).ConfigureAwait(false);
      }
    }
    public async Task SendEmailAsync(string email, string subject, string message, bool plaintext)
    {
      // Plug in your email service here to send an email.
      //return Task.FromResult(0);
      var emailMessage = new MimeMessage();
      emailMessage.From.Add(new MailboxAddress(_settings.SmtpSettings.DisplayName, _settings.SmtpSettings.From));
      emailMessage.To.Add(new MailboxAddress("", email));
      emailMessage.Subject = subject;
      emailMessage.Body = new TextPart("plain") { Text = message };
      using (var client = new SmtpClient())
      {
        client.AuthenticationMechanisms.Remove("XOAUTH2");
        await client.ConnectAsync(_settings.SmtpSettings.Host, _settings.SmtpSettings.Port, SecureSocketOptions.None)
          .ConfigureAwait(false);
        await client.AuthenticateAsync(_settings.SmtpSettings.UserName, _settings.SmtpSettings.Password);
        await client.SendAsync(emailMessage).ConfigureAwait(false);
        await client.DisconnectAsync(true).ConfigureAwait(false);
      }

    }

    public async Task SendSmsAsync(string number, string message)
    {
      // Plug in your SMS service here to send a text message.
      //return Task.FromResult(0);
      if (string.IsNullOrWhiteSpace(number))
      {
        throw new ArgumentException("number was not provided");
      }
      if (string.IsNullOrWhiteSpace(message))
      {
        throw new ArgumentException("message was not provided");
      }
      var keyValues = new List<KeyValuePair<string, string>>
      {
        new KeyValuePair<string, string>("To", number),
        new KeyValuePair<string, string>("From", _settings.SmsSettings.From),
        new KeyValuePair<string, string>("Body", message)
      };
      var content = new FormUrlEncodedContent(keyValues);
      using (var client = new HttpClient { BaseAddress = new Uri(_settings.SmsSettings.BaseUri) })
      {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_settings.SmsSettings.Sid}:{_settings.SmsSettings.Token}")));
        var response = await client.PostAsync(_settings.SmsSettings.RequestUri, content).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
          // Handle fail
        }
      }
    }
  }
}
