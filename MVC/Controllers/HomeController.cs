using Microsoft.AspNetCore.Mvc;
using MVC.Models;
using MVC.Services;

namespace MVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly IUtilityService _utilityService;
        private readonly ISmsSender _smsSender;

        public HomeController(
            IUtilityService utilityService,
            ISmsSender smsSender)
        {
            _utilityService = utilityService;
            _smsSender = smsSender;
        }

        public IActionResult Index()
        {
            _utilityService.SetViewCookie(HttpContext, "Home View", "HomeView", LogType.Information);
            return View();
        }

        public IActionResult About()
        {
            _utilityService.SetViewCookie(HttpContext, "About View", "AboutView", LogType.Information);
            ViewData["Message"] = "Your application description page.";
            return View();
        }

        public IActionResult Contact()
        {
            _utilityService.SetViewCookie(HttpContext, "Contact View", "ContactView", LogType.Information);
            ViewData["Message"] = "Your contact page.";
            return View();
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}
