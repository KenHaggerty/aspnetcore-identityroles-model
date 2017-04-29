using MVC.Models;
using MVC.Models.MemberViewModels;
using MVC.Models.SettingsModels;
using MVC.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace MVC.Controllers
{
  [Authorize]
  public class MemberController : Controller
  {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;
    private readonly IUtilityService _utilityService;
    private readonly Settings _settings;

    public MemberController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<ApplicationRole> roleManager,
        IEmailSender emailSender,
        ISmsSender smsSender,
        IUtilityService utilityService,
        IOptionsSnapshot<Settings> settings)
    {
      _userManager = userManager;
      _signInManager = signInManager;
      _roleManager = roleManager;
      _emailSender = emailSender;
      _smsSender = smsSender;
      _utilityService = utilityService;
      _settings = settings.Value;

    }

    // GET: /<controller>/
    public async Task<IActionResult> Index()
    {
      ViewData["Theme"] = Request.Cookies["TempThemeCookie"];
      _utilityService.SetViewCookie(HttpContext, "Member Index View", "MemberIndexView", LogType.Information);
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        ModelState.AddModelError("", "The current user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Member Error", "Member Index current user was not found.", LogType.Error, true);
        return View();
      }
      var roles = await _userManager.GetRolesAsync(user);
      var list = roles.OrderBy(q => q).ToList();
      var userLogins = await _userManager.GetLoginsAsync(user);
      //var exlogins = "";
      //foreach (UserLoginInfo el in userLogins)
      //{
      //    exlogins += el.LoginProvider[0] + ",";
      //}
      var mm = new MemberIndexViewModel(user, list, userLogins);
      return View(mm);
    }

    #region Helpers

    private bool IsDate(string dateString)
    {
      string format = "yyyy-MM-dd";
      DateTime dateTime;
      if (DateTime.TryParseExact(dateString, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out dateTime))
      {
        return true;
      }
      else
      {
        return false;
      }
    }
    private string AddErrors(IdentityResult result)
    {
      var sb = new StringBuilder();
      foreach (var error in result.Errors)
      {
        ModelState.AddModelError(string.Empty, error.Description);
        sb.Append(error.Description + ", ");
      }
      return sb.ToString();
    }

    //public enum AdminMessageId
    //{
    //    AddPhoneSuccess,
    //    AddLoginSuccess,
    //    ChangePasswordSuccess,
    //    SetTwoFactorSuccess,
    //    SetPasswordSuccess,
    //    RemoveLoginSuccess,
    //    RemovePhoneSuccess,
    //    Error
    //}

    private Task<ApplicationUser> GetCurrentUserAsync()
    {
      return _userManager.GetUserAsync(HttpContext.User);
    }

    #endregion

  }
}
