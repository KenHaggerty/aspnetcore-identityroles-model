using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MVC.Models
{
    public class LogEntry
    {
        [Key]
        public string ID { get; set; }
        [Required]
        [Column(TypeName = "smalldatetime")]
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
        public string Host { get; set; }
        public string ExceptionString { get; set; }
        [Required]
        public LogType LogType { get; set; }
        
        public LogEntry() { }

        public LogEntry(string subject, string message, string userName, string controller, string action, string host, string exceptionString, LogType type = LogType.Information)
        {
            //ID = Guid.NewGuid().ToString();
            CreateDate = DateTime.UtcNow;
            Subject = subject;
            Message = message;
            UserName = userName;
            Controller = controller;
            Action = action;
            Host = host;
            ExceptionString = exceptionString;
            LogType = type;
        }
    }

    public enum LogType
    {
        All,
        Critical,
        Error,
        Information
    }
}