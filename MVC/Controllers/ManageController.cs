using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MVC.Models;
using MVC.Models.ManageViewModels;
using MVC.Models.SettingsModels;
using MVC.Services;

namespace MVC.Controllers
{
  [Authorize]
  public class ManageController : Controller
  {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly string _externalCookieScheme;
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;

    //private readonly ILogger _logger;
    private readonly IUtilityService _utilityService;
    private readonly Settings _settings;

    public ManageController(
      UserManager<ApplicationUser> userManager,
      SignInManager<ApplicationUser> signInManager,
      IOptions<IdentityCookieOptions> identityCookieOptions,
      IEmailSender emailSender,
      ISmsSender smsSender,
      IUtilityService utilityService,
      IOptionsSnapshot<Settings> settings)
    {
      _userManager = userManager;
      _signInManager = signInManager;
      _externalCookieScheme = identityCookieOptions.Value.ExternalCookieAuthenticationScheme;
      _emailSender = emailSender;
      _smsSender = smsSender;
      _utilityService = utilityService;
      _settings = settings.Value;
      //_logger = loggerFactory.CreateLogger<ManageController>();
    }

    //
    // GET: /Manage/Index
    [HttpGet]
    public async Task<IActionResult> Index(ManageMessageId? message = null)
    {
      ViewData["StatusMessage"] =
          message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
          : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
          : message == ManageMessageId.SetTwoFactorSuccess ? "Your two-factor authentication provider has been set."
          : message == ManageMessageId.Error ? "An error has occurred."
          : message == ManageMessageId.AddPhoneSuccess ? "Your phone number was added."
          : message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed."
          : "";


      _utilityService.SetViewCookie(HttpContext, "Manage Index View", "ManageIndexView", LogType.Information);
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      var model = new IndexViewModel
      {
        HasPassword = await _userManager.HasPasswordAsync(user),
        PhoneNumber = await _userManager.GetPhoneNumberAsync(user),
        TwoFactor = await _userManager.GetTwoFactorEnabledAsync(user),
        Logins = await _userManager.GetLoginsAsync(user),
        BrowserRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user)
      };
      return View(model);
    }

    //
    // POST: /Manage/RemoveLogin
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveLogin(RemoveLoginViewModel account)
    {
      ManageMessageId? message = ManageMessageId.Error;
      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        var result = await _userManager.RemoveLoginAsync(user, account.LoginProvider, account.ProviderKey);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          _utilityService.InsertLogEntry(HttpContext, account.LoginProvider + " Login Deleted", user.UserName + " - removed " + account.LoginProvider + ".", LogType.Information);
          message = ManageMessageId.RemoveLoginSuccess;
        }
      }
      return RedirectToAction(nameof(ManageLogins), new { Message = message });
    }

    //
    // GET: /Manage/AddPhoneNumber
    public IActionResult AddPhoneNumber()
    {
      _utilityService.SetViewCookie(HttpContext, "Add Phone Number View", "AddPhoneNumberView", LogType.Information);
      return View();
    }

    //
    // POST: /Manage/AddPhoneNumber
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }
      // Generate the token and send it
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);

      //await _smsSender.SendSmsAsync(model.PhoneNumber, "Your security code is: " + code);
      await Task.Run(() => { Task.Delay(500); });

      return RedirectToAction(nameof(VerifyPhoneNumber), new { PhoneNumber = model.PhoneNumber });
    }

    //
    // POST: /Manage/EnableTwoFactorAuthentication
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableTwoFactorAuthentication()
    {
      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        await _signInManager.SignInAsync(user, isPersistent: false);
        //_logger.LogInformation(1, "User enabled two-factor authentication.");
        _utilityService.InsertLogEntry(HttpContext, "Enable 2 Factor", user.UserName + " enabled 2 factor authentication.", LogType.Information);
      }
      return RedirectToAction(nameof(Index), "Manage");
    }

    //
    // POST: /Manage/DisableTwoFactorAuthentication
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DisableTwoFactorAuthentication()
    {
      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _signInManager.SignInAsync(user, isPersistent: false);
        //_logger.LogInformation(2, "User disabled two-factor authentication.");
        _utilityService.InsertLogEntry(HttpContext, "Disable 2 Factor", user.UserName + " disabled 2 factor authentication.", LogType.Information);
      }
      return RedirectToAction(nameof(Index), "Manage");
    }

    //
    // GET: /Manage/VerifyPhoneNumber
    [HttpGet]
    public async Task<IActionResult> VerifyPhoneNumber(string phoneNumber)
    {
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, phoneNumber);
      // Send an SMS to verify the phone number
      _utilityService.InsertLogEntry(HttpContext, "Phone Code Sent", user.UserName + " sent code to verify " + phoneNumber + ".", LogType.Information);
      return phoneNumber == null ? View("Error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
    }

    //
    // POST: /Manage/VerifyPhoneNumber
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }
      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        var result = await _userManager.ChangePhoneNumberAsync(user, model.PhoneNumber, model.Code);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          _utilityService.InsertLogEntry(HttpContext, "Phone Updated", user.UserName + " updated phone to " + model.PhoneNumber + ".", LogType.Information);
          return RedirectToAction(nameof(Index), new { Message = ManageMessageId.AddPhoneSuccess });
        }
      }
      // If we got this far, something failed, redisplay the form
      ModelState.AddModelError(string.Empty, "Failed to verify phone number");
      return View(model);
    }

    //
    // POST: /Manage/RemovePhoneNumber
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemovePhoneNumber()
    {
      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        var result = await _userManager.SetPhoneNumberAsync(user, null);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          _utilityService.InsertLogEntry(HttpContext, "Phone Deleted", user.UserName + " deleted phone.", LogType.Information);
          return RedirectToAction(nameof(Index), new { Message = ManageMessageId.RemovePhoneSuccess });
        }
      }
      return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    //
    // GET: /Manage/ChangePassword
    [HttpGet]
    public IActionResult ChangePassword()
    {
      _utilityService.SetViewCookie(HttpContext, "Change Password View", "ChangePasswordView", LogType.Information);
      return View();
    }

    //
    // POST: /Manage/ChangePassword
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }
      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          //_logger.LogInformation(3, "User changed their password successfully.");
          _utilityService.InsertLogEntry(HttpContext, "Password Updated", user.UserName + " reset their password successfully.", LogType.Information);
          return RedirectToAction(nameof(Index), new { Message = ManageMessageId.ChangePasswordSuccess });
        }
        AddErrors(result);
        return View(model);
      }
      return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    //
    // GET: /Manage/SetPassword
    [HttpGet]
    public IActionResult SetPassword()
    {
      _utilityService.SetViewCookie(HttpContext, "Set Password View", "SetPasswordView", LogType.Information);
      return View();
    }

    //
    // POST: /Manage/SetPassword
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }

      var user = await GetCurrentUserAsync();
      if (user != null)
      {
        var result = await _userManager.AddPasswordAsync(user, model.NewPassword);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          _utilityService.InsertLogEntry(HttpContext, "Password Set", user.UserName + " set their password successfully.", LogType.Information);
          return RedirectToAction(nameof(Index), new { Message = ManageMessageId.SetPasswordSuccess });
        }
        AddErrors(result);
        return View(model);
      }
      return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    //GET: /Manage/ManageLogins
    [HttpGet]
    public async Task<IActionResult> ManageLogins(ManageMessageId? message = null)
    {
      ViewData["StatusMessage"] =
          message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
          : message == ManageMessageId.AddLoginSuccess ? "The external login was added."
          : message == ManageMessageId.Error ? "An error has occurred."
          : "";

      _utilityService.SetViewCookie(HttpContext, "Manage Logins View", "ManageLoginsView", LogType.Information);
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      var userLogins = await _userManager.GetLoginsAsync(user);
      var otherLogins = _signInManager.GetExternalAuthenticationSchemes().Where(auth => userLogins.All(ul => auth.AuthenticationScheme != ul.LoginProvider)).ToList();
      ViewData["ShowRemoveButton"] = user.PasswordHash != null || userLogins.Count > 1;
      return View(new ManageLoginsViewModel
      {
        CurrentLogins = userLogins,
        OtherLogins = otherLogins
      });
    }

    //
    // POST: /Manage/LinkLogin
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LinkLogin(string provider)
    {
      // Clear the existing external cookie to ensure a clean login process
      await HttpContext.Authentication.SignOutAsync(_externalCookieScheme);

      // Request a redirect to the external login provider to link a login for the current user
      var redirectUrl = Url.Action(nameof(LinkLoginCallback), "Manage");
      var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, _userManager.GetUserId(User));
      _utilityService.InsertLogEntry(HttpContext, provider + " Login Challenge Sent", User.Identity.Name + " - challenged " + provider + ".", LogType.Information);
      return Challenge(properties, provider);
    }

    //
    // GET: /Manage/LinkLoginCallback
    [HttpGet]
    public async Task<ActionResult> LinkLoginCallback()
    {
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      var info = await _signInManager.GetExternalLoginInfoAsync(await _userManager.GetUserIdAsync(user));
      if (info == null)
      {
        return RedirectToAction(nameof(ManageLogins), new { Message = ManageMessageId.Error });
      }
      var result = await _userManager.AddLoginAsync(user, info);
      var message = ManageMessageId.Error;
      if (result.Succeeded)
      {
        message = ManageMessageId.AddLoginSuccess;
        // Clear the existing external cookie to ensure a clean login process
        await HttpContext.Authentication.SignOutAsync(_externalCookieScheme);
        _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Added", user.UserName + " - added " + info.LoginProvider + ".", LogType.Information);
      }
      return RedirectToAction(nameof(ManageLogins), new { Message = message });
    }

    #region Helpers

    private void AddErrors(IdentityResult result)
    {
      foreach (var error in result.Errors)
      {
        ModelState.AddModelError(string.Empty, error.Description);
      }
    }

    public enum ManageMessageId
    {
      AddPhoneSuccess,
      AddLoginSuccess,
      ChangePasswordSuccess,
      SetTwoFactorSuccess,
      SetPasswordSuccess,
      RemoveLoginSuccess,
      RemovePhoneSuccess,
      Error
    }

    private Task<ApplicationUser> GetCurrentUserAsync()
    {
      return _userManager.GetUserAsync(HttpContext.User);
    }

    #endregion
  }
}
