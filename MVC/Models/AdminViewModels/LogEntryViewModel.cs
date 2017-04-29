using System;
using System.ComponentModel.DataAnnotations;

namespace MVC.Models.AdminViewModels
{
    public class LogEntryViewModel
    {        
        //SendAdminNotificationEmail(subject, message, country, controller, action, username, type, queryJSON, cookieJSON, headerJSON, ipinfoJSON, host, agent, w, h);
        [Key]
        public string ID { get; set; }
        [Required]
        public DateTime CreateDate { get; set; }
        [Required]
        public string Subject { get; set; }
        [Required]
        public string Message { get; set; }
        [Required]
        public string UserName { get; set; }
        
        [Required]
        public string Controller { get; set; }
        [Required]
        public string Action { get; set; }
        
        public string ExceptionString { get; set; }
        [Required]
        public LogType LogType { get; set; }        
        
        public LogEntryViewModel() { }

        public LogEntryViewModel(string id, DateTime createdate, string host, string subject, string message, string username, string country, string agent, string ipinfoJSON,
            string controller, string action, string headerJSON, string queryJSON, string exceptionString, LogType type = LogType.Information, int vpwidth = 0, int vpheight = 0)
        {
            ID = id;
            CreateDate = createdate;
            Subject = subject;
            Message = message;
            UserName = username;
            Controller = controller;
            Action = action;
            ExceptionString = exceptionString;
            LogType = type;
        }
    }
}
