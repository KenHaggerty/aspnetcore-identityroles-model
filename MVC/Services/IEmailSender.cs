using System.Threading.Tasks;

namespace MVC.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
        Task SendEmailAsync(string email, string subject, string message, bool plaintext);
    }
}
