using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using MVC.Models;
using MVC.Models.AccountViewModels;
using MVC.Models.SettingsModels;
using MVC.Services;
using System;
using System.Text;

namespace MVC.Controllers
{
  [Authorize]
  public class AccountController : Controller
  {
    private readonly IUtilityService _utilityService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;
    private readonly Settings _settings;
    private readonly string _externalCookieScheme;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<ApplicationRole> roleManager,
        IOptions<IdentityCookieOptions> identityCookieOptions,
        IEmailSender emailSender,
        ISmsSender smsSender,
        IUtilityService utilityService,
        IOptionsSnapshot<Settings> settings)
    {
      _userManager = userManager;
      _signInManager = signInManager;
      _roleManager = roleManager;
      _externalCookieScheme = identityCookieOptions.Value.ExternalCookieAuthenticationScheme;
      _emailSender = emailSender;
      _smsSender = smsSender;
      _utilityService = utilityService;
      _settings = settings.Value;
    }

    //
    // GET: /Account/Login
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string returnUrl = null)
    {
      // Clear the existing external cookie to ensure a clean login process
      await HttpContext.Authentication.SignOutAsync(_externalCookieScheme);

      ViewData["ReturnUrl"] = returnUrl;
      ViewBag.ShowResend = false;
      ViewBag.UserName = string.Empty;
      _utilityService.SetViewCookie(HttpContext, "Login View", "LoginView", LogType.Information);
      return View();
    }

    //
    // POST: /Account/Login
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      ViewBag.ShowResend = false;
      if (ModelState.IsValid)
      {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user == null)
        {
          ModelState.AddModelError(string.Empty, "Invalid login attempt.");
          _utilityService.InsertLogEntry(HttpContext, "Invalid Login Attempt", model.UserName + " login attempt is invalid.",
            LogType.Information);
          return View(model);
        }
        // This doesn't count login failures towards account lockout
        // To enable password failures to trigger account lockout, set lockoutOnFailure: true
        var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe,
          lockoutOnFailure: true);
        if (result.Succeeded)
        {
          // Require the user to have a confirmed email before they can log on.
          //if (!await _userManager.IsEmailConfirmedAsync(user))
          //{
          //    _utilityService.InsertLogEntry(HttpContext, "Email Not Confirmed", model.UserName + " - email not confirmed." +
          //      " Show resend.", LogType.AcEmailNotConfirmed);
          //    ViewBag.ShowResend = true;
          //    ViewBag.UserName = model.UserName;
          //    ModelState.AddModelError(string.Empty, "You must have a confirmed email to log in.");
          //    return View(model);
          //}
          if (user.MustChangePassword)
          {
            _utilityService.InsertLogEntry(HttpContext, "Must Change Password", model.UserName + " - must change password.",
              LogType.Information);
            return RedirectToAction("MustChangePassword", "Account", new RouteValueDictionary(new { id = model.Password,
              returnUrl = returnUrl }));
          }
          _utilityService.InsertLogEntry(HttpContext, "Logged In", model.UserName + " logged in.", LogType.Information);
          return RedirectToLocal(returnUrl);
        }
        else if (result.RequiresTwoFactor)
        {
          _utilityService.InsertLogEntry(HttpContext, "Two Factor Required", model.UserName + " requires two factor verification.",
            LogType.Information);
          return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
        }
        else if (result.IsLockedOut)
        {
          _utilityService.InsertLogEntry(HttpContext, "Login Lockout", model.UserName + " account locked out.", LogType.Error, true);
          return View("Lockout");
        }
        else if (result.IsNotAllowed)
        {
          if (!await _userManager.IsEmailConfirmedAsync(user))
          {
            _utilityService.InsertLogEntry(HttpContext, "Email Not Confirmed", model.UserName + " - email not confirmed. Show resend.",
              LogType.Information);
            ViewBag.ShowResend = true;
            ViewBag.UserName = model.UserName;
            ModelState.AddModelError(string.Empty, "You must have a confirmed email to log in.");
            return View(model);
          }
        }
        else
        {
          ModelState.AddModelError(string.Empty, "Invalid login attempt.");
          _utilityService.InsertLogEntry(HttpContext, "Invalid Login Attempt", model.UserName + " login attempt is invalid.",
            LogType.Information);
          return View(model);
        }
      }
      // If we got this far, something failed, redisplay form
      return View(model);
    }

    //
    // AJAX POST: /Account/LinkExternal
    // Called by AJAX must return JSON
    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> LinkExternal()
    {
      string email = HttpContext.Request.Form["LoginEmailHidden"];
      string returnUrl = HttpContext.Request.Form["LoginReturnURLHidden"];
      string username = HttpContext.Request.Form["LoginUserNameTextBox"];
      string password = HttpContext.Request.Form["LoginPasswordTextBox"];
      var rememberme = false;
      if (!string.IsNullOrEmpty(HttpContext.Request.Form["RememberMeCheckbox"]) &&
        Request.Form["RememberMeCheckbox"] == "on")
      {
        rememberme = true;
      }
      ApplicationUser user = await _userManager.FindByNameAsync(username);
      if (user != null)
      {
        var result = await _signInManager.PasswordSignInAsync(username, password, rememberme, lockoutOnFailure: true);
        if (result.Succeeded)
        {
          // Get the information about the user from the external login provider
          var info = await _signInManager.GetExternalLoginInfoAsync();
          if (info == null)
          {
            _utilityService.InsertLogEntry(HttpContext, "External Login Error", "LinkExternal post info is null.", LogType.Error, true);
            return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>You are logged in" +
              " but there was an error linking the external service.</li></ul>" });
          }
          var addresult = await _userManager.AddLoginAsync(user, info);
          if (addresult.Succeeded)
          {
            switch (info.LoginProvider)
            {
              case "Facebook":
                _utilityService.InsertLogEntry(HttpContext, "Facebook Login Added", user.UserName + " - added Facebook.",
                  LogType.Information);
                break;
              case "GitHub":
                _utilityService.InsertLogEntry(HttpContext, "GitHub Login Added", user.UserName + " - added GitHub.",
                  LogType.Information);
                break;
              case "Google":
                _utilityService.InsertLogEntry(HttpContext, "Google Login Added", user.UserName + " - added Google.",
                  LogType.Information);
                break;
              case "Microsoft":
                _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Added", user.UserName + " - added Microsoft.",
                  LogType.Information);
                break;
              case "Twitter":
                _utilityService.InsertLogEntry(HttpContext, "Twitter Login Added", user.UserName + " - added Twitter.",
                  LogType.Information);
                break;
              default:
                _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Added", user.UserName + " - added " +
                  info.LoginProvider + ".", LogType.Information);
                break;
            }
          }
          else
          {
            switch (info.LoginProvider)
            {
              case "Facebook":
                _utilityService.InsertLogEntry(HttpContext, "Facebook Login Error", "LinkExternal " + user.UserName +
                  " - Facebook result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "GitHub":
                _utilityService.InsertLogEntry(HttpContext, "GitHub Login Error", "LinkExternal " + user.UserName +
                  " - GitHub result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "Google":
                _utilityService.InsertLogEntry(HttpContext, "Google Login Error", "LinkExternal " + user.UserName +
                  " - Google result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "Microsoft":
                _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Error", "LinkExternal " + user.UserName +
                  " - Microsoft result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "Twitter":
                _utilityService.InsertLogEntry(HttpContext, "Twitter Login Error", "LinkExternal " + user.UserName +
                  " - Twitter result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              default:
                _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Error", "LinkExternal " + user.UserName +
                  " - " + info.LoginProvider + " result = " + addresult.Errors.ToString(), LogType.Error);
                break;
            }
          }
          // Require the user to have a confirmed email before they can log on.
          //if (!await _userManager.IsEmailConfirmedAsync(user))
          //{
          //    _utilityService.InsertLogEntry(HttpContext, "Email Not Confirmed", username + " - email not confirmed. Show error.",
          //      LogType.AcEmailNotConfirmed);
          //    ViewData["ErrorMessage"] = "<ul class='text-danger validation-summary-errors'><li>You must have a confirmed email" +
          //    " to log in.</li><li>Cancel then attempt local Log in for resend option.</li></ul>";
          //    ViewData["ReturnUrl"] = returnUrl;
          //    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });
          //}

          if (user.MustChangePassword)
          {
            _utilityService.InsertLogEntry(HttpContext, "Must Change Password", username + " - must change password.",
              LogType.Information);
            return Json(new { success = true, responseText = $"/Account/MustChangePassword?id={password}&returnUrl={returnUrl}" });
          }
          _utilityService.InsertLogEntry(HttpContext, "Logged In", username + " logged in.", LogType.Information);
          return Json(new { success = true, responseText = returnUrl });
        }
        else if (result.RequiresTwoFactor)
        {
          // Get the information about the user from the external login provider
          var info = await _signInManager.GetExternalLoginInfoAsync();
          if (info == null)
          {
            _utilityService.InsertLogEntry(HttpContext, "External Login Error", "LinkExternal post info is null.", LogType.Error, true);
            return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>You are logged in" +
              " but there was an error linking the external service.</li></ul>"
            });
          }
          var addresult = await _userManager.AddLoginAsync(user, info);
          if (addresult.Succeeded)
          {
            switch (info.LoginProvider)
            {
              case "Facebook":
                _utilityService.InsertLogEntry(HttpContext, "Facebook Login Added", user.UserName + " - added Facebook. Requires" +
                  " Two Factor.", LogType.Information);
                break;
              case "GitHub":
                _utilityService.InsertLogEntry(HttpContext, "GitHub Login Added", user.UserName + " - added GitHub. Requires Two Factor.",
                  LogType.Information);
                break;
              case "Google":
                _utilityService.InsertLogEntry(HttpContext, "Google Login Added", user.UserName + " - added Google. Requires Two Factor.",
                  LogType.Information);
                break;
              case "Microsoft":
                _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Added", user.UserName + " - added Microsoft. Requires Two" +
                  " Factor.", LogType.Information);
                break;
              case "Twitter":
                _utilityService.InsertLogEntry(HttpContext, "Twitter Login Added", user.UserName + " - added Twitter. Requires Two Factor.",
                  LogType.Information);
                break;
              default:
                _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Added", user.UserName + " - added " +
                  info.LoginProvider + ". Requires Two Factor.", LogType.Information);
                break;
            }
          }
          else
          {
            switch (info.LoginProvider)
            {
              case "Facebook":
                _utilityService.InsertLogEntry(HttpContext, "Facebook Login Error", "LinkExternal Requires Two Factor. " + user.UserName +
                  " - Facebook result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "GitHub":
                _utilityService.InsertLogEntry(HttpContext, "GitHub Login Error", "LinkExternal Requires Two Factor. " + user.UserName +
                  " - GitHub result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "Google":
                _utilityService.InsertLogEntry(HttpContext, "Google Login Error", "LinkExternal Requires Two Factor. " + user.UserName +
                  " - Google result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "Microsoft":
                _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Error", "LinkExternal Requires Two Factor. " + user.UserName +
                  " - Microsoft result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              case "Twitter":
                _utilityService.InsertLogEntry(HttpContext, "Twitter Login Error", "LinkExternal Requires Two Factor. " + user.UserName +
                  " - Twitter result = " + addresult.Errors.ToString(), LogType.Error);
                break;
              default:
                _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Error", "LinkExternal Requires Two Factor. " +
                  user.UserName + " - " + info.LoginProvider + " result = " + addresult.Errors.ToString(), LogType.Error);
                break;
            }
            //return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>You are logged in" +
            //  " but there was an error linking the external service.</li></ul>" });
          }

          _utilityService.InsertLogEntry(HttpContext, "Two Factor Required", username + " requires two factor verification.",
            LogType.Information);
          return Json(new { success = true, responseText = $"/Account/SendCode?returnUrl={returnUrl}&RememberMe={rememberme}" });
        }
        else if (result.IsLockedOut)
        {
          _utilityService.InsertLogEntry(HttpContext, "Login Lockout", username + " account locked out.", LogType.Error, true);
          return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>This account has been" +
              " locked out.</li><li>Please try again later.</li></ul>"
          });
        }
        else if (result.IsNotAllowed)
        {
          if (!await _userManager.IsEmailConfirmedAsync(user))
          {
            _utilityService.InsertLogEntry(HttpContext, "Email Not Confirmed", username + " - email not confirmed. Show error.",
              LogType.Information);
            return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>You must have a" +
              " confirmed email to log in.</li><li>Cancel then attempt local Log in for resend option.</li></ul>"
            });
          }
          else
          {
            _utilityService.InsertLogEntry(HttpContext, "External Login Error", "LinkExternal post IsNotAllowed and IsEmailConfirmed.", LogType.Error, true);
            return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>There was an error linking the external service.</li><li>Please contact support.</li></ul>" });
          }
        }
        else
        {
          _utilityService.InsertLogEntry(HttpContext, "Invalid Login Attempt", username + " login attempt is invalid.",
            LogType.Information);
          return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>Invalid login" +
              " attempt.</li></ul>"
          });
        }
      }
      else
      {
        _utilityService.InsertLogEntry(HttpContext, "External Login Error", $"LinkExternal post user={username} is null.",
          LogType.Error, true);
        return Json(new { success = false, responseText = "<ul class='text-danger validation-summary-errors'><li>Invalid login" +
              " attempt.</li></ul>"
        });
      }
    }

    //
    // GET: /Account/MustChangePassword
    [HttpGet]
    public IActionResult MustChangePassword(string id = "", string returnUrl = null)
    {
      ViewData["Theme"] = Request.Cookies["TempThemeCookie"];
      _utilityService.SetViewCookie(HttpContext, "Must Change Password View", "PasswordMustChangeView",
        LogType.Information);
      return View(new MustChangePasswordViewModel(id, returnUrl));
    }

    //
    // POST: /Account/MustChangePassword
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> MustChangePassword(MustChangePasswordViewModel model)
    {
      ViewData["Theme"] = Request.Cookies["TempThemeCookie"];
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Must Change Password Error", "MustChangePassword post model state is invalid.",
          LogType.Error, true);
        return View(model);
      }
      try
      {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
          _utilityService.InsertLogEntry(HttpContext, "Must Change Password Error", "MustChangePassword post user not found.",
            LogType.Error, true);
          return View("Error");
        }
        var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        if (result.Succeeded)
        {
          user.MustChangePassword = false;
          await _userManager.UpdateAsync(user);
          _utilityService.InsertLogEntry(HttpContext, "Must Change Password Success", user.UserName +
            " - changed password successfully.", LogType.Information);
          //return RedirectToAction("Index", "Manage");
          return RedirectToLocal(model.ReturnURL);
        }
        else
        {
          var err = AddErrors(result);
          _utilityService.InsertLogEntry(HttpContext, "Must Change Password Error", "MustChangePassword post result = " +
            err, LogType.Error, true);
          return View(model);
        }
      }
      catch (Exception ex)
      {
        _utilityService.InsertLogEntry(HttpContext, "Must Change Password Error", "MustChangePassword post threw exception.",
          LogType.Error, true, ex);
        await _signInManager.SignOutAsync();
        return RedirectToAction("Login", "Account");
      }
    }

    //
    // GET: /Account/Register
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register(string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      _utilityService.SetViewCookie(HttpContext, "Register View", "RegisterView", LogType.Information);
      return View();
    }

    //
    // POST: /Account/Register
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Register Error", "Register post model state is invalid.", LogType.Error, true);
        return View(model);
      }
      var user = new ApplicationUser { UserName = model.UserName, Email = model.Email };
      var result = await _userManager.CreateAsync(user, model.Password);
      if (result.Succeeded)
      {
        if (!_roleManager.RoleExistsAsync("AdminRole").Result)
        {
          var role = new ApplicationRole() { Name = "AdminRole", Description = "Application Role to perform administrator functions." };
          var roleResult = await _roleManager.CreateAsync(role);
          if (!roleResult.Succeeded)
          {
            ModelState.AddModelError("", "Error while creating Admin role!");
            _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", model.UserName + " error while creating Admin role.",
              LogType.Error, true);
            return View(model);
          }
          _utilityService.InsertLogEntry(HttpContext, "Admin Role Added", model.UserName + " created Admin role.",
            LogType.Information);
        }
        if (!_roleManager.RoleExistsAsync("LogViewRole").Result)
        {
          var role = new ApplicationRole() { Name = "LogViewRole", Description = "Application Role to view the Event Log." };
          var roleResult = await _roleManager.CreateAsync(role);
          if (!roleResult.Succeeded)
          {
            ModelState.AddModelError("", "Error while creating LogView role.");
            _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", model.UserName + " - error while creating LogView role.",
              LogType.Error, true);
            return View(model);
          }
          else
          {
            _utilityService.InsertLogEntry(HttpContext, "Admin Role Added", user.UserName + " created LogView role.",
              LogType.Information);
          }
        }
        if (!_roleManager.RoleExistsAsync("ManagerRole").Result)
        {
          var role = new ApplicationRole() { Name = "ManagerRole", Description = "Application Role to perform user but not role" +
              " functions."
          };
          var roleResult = await _roleManager.CreateAsync(role);
          if (!roleResult.Succeeded)
          {
            ModelState.AddModelError("", "Error while creating Manager role!");
            _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", model.UserName + " error while creating Manager role.",
              LogType.Error, true);
            return View(model);
          }
          _utilityService.InsertLogEntry(HttpContext, "Admin Role Added", model.UserName + " created Manager role.",
            LogType.Information);
        }
        if (await _userManager.Users.ToAsyncEnumerable().Count() == 1)
        {
          user.LockoutEnabled = false;
          await _userManager.UpdateAsync(user);
          var userResult = await _userManager.AddToRoleAsync(user, "AdminRole");
          if (!userResult.Succeeded)
          {
            var uerr = AddErrors(userResult);
            _utilityService.InsertLogEntry(HttpContext, "Admin User Role Error", model.UserName + " error add first user to Admin" +
              " role result = " + uerr, LogType.Error, true);
            return View(model);
          }
          _utilityService.InsertLogEntry(HttpContext, "Admin User Role Added", model.UserName + " added first user to Admin role.",
            LogType.Information);
          user.EmailConfirmed = true;
          await _userManager.UpdateAsync(user);
          return RedirectToAction("Login", "Account");
        }
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code },
          protocol: HttpContext.Request.Scheme);
        var sb = new StringBuilder("<html><body><div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>Email" +
              " Verification for " + _settings.Name);
        sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
        sb.Append(user.UserName);
        sb.Append(",<br/>Thank you for your interest. Please click <a href='");
        sb.Append(callbackUrl);
        sb.Append("'>here</a> to verify your email.<br/> You must verify your email before you log in to " + _settings.Name +
          ".<br/><br/>If you have any problem, please let me know.<br/>");
        sb.Append("Email  <a href='mailto:" + _settings.SupportEmail + "? subject=Verify Email'>" + _settings.SupportEmail +
          "</a><br/><br/>Thank you again,<br/>" + _settings.SupportName + "<br/><br/>");
        sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

        //await _emailSender.SendEmailAsync(model.Email, "Email Verification for " + _settings.Name, sb.ToString());
        await Task.Run(() => { Task.Delay(500); });

        _utilityService.InsertLogEntry(HttpContext, "Register Added", user.UserName + " created a new account with password.",
          LogType.Information, true);
        return View("VerifyEmailConfirmation");
      }
      var err = AddErrors(result);
      _utilityService.InsertLogEntry(HttpContext, "Register Error", "Register post result = " + err, LogType.Error, true);

      // If we got this far, something failed, redisplay form
      return View(model);
    }

    //
    // POST: /Account/Logout
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
      //_logger.LogInformation(4, "User logged out.");
      _utilityService.InsertLogEntry(HttpContext, "Logout", HttpContext.User.Identity.Name + " logged out.", LogType.Information);
      await _signInManager.SignOutAsync();
      return RedirectToAction(nameof(HomeController.Index), "Home");
    }

    //
    // POST: /Account/ExternalLogin
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider, string returnUrl = null)
    {
      // Request a redirect to the external login provider.
      var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { ReturnUrl = returnUrl });
      var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
      var message = $"New user challenged {provider}.";
      switch (provider)
      {
        case "Facebook":
          _utilityService.InsertLogEntry(HttpContext, "Facebook Login Challenge Sent", message, LogType.Information);
          break;
        case "GitHub":
          _utilityService.InsertLogEntry(HttpContext, "GitHub Login Challenge Sent", message, LogType.Information);
          break;
        case "Google":
          _utilityService.InsertLogEntry(HttpContext, "Google Login Challenge Sent", message, LogType.Information);
          break;
        case "Microsoft":
          _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Challenge Sent", message, LogType.Information);
          break;
        case "Twitter":
          _utilityService.InsertLogEntry(HttpContext, "Twitter Login Challenge Sent", message, LogType.Information);
          break;
        default:
          _utilityService.InsertLogEntry(HttpContext, provider + " Login Challenge Sent", message, LogType.Information);
          break;
      }

      return Challenge(properties, provider);
    }

    //
    // GET: /Account/ExternalLoginCallback
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
    {
      if (remoteError != null)
      {
        ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
        _utilityService.InsertLogEntry(HttpContext, "External Login Error",
          $"ExternalLoginCallback error from external provider: {remoteError}", LogType.Error, true);
        return View(nameof(Login));
      }
      var info = await _signInManager.GetExternalLoginInfoAsync();
      if (info == null)
      {
        _utilityService.InsertLogEntry(HttpContext, "External Login Error", "ExternalLoginCallback info is null.",
          LogType.Error, true);
        return RedirectToAction(nameof(Login));
      }

      // Sign in the user with this external login provider if the user already has a login.
      var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
      if (result.Succeeded)
      {
        var message = $"User logged in with {info.LoginProvider} provider.";
        switch (info.LoginProvider)
        {
          case "Facebook":
            _utilityService.InsertLogEntry(HttpContext, "Facebook Login", message, LogType.Information);
            break;
          case "GitHub":
            _utilityService.InsertLogEntry(HttpContext, "GitHub Login", message, LogType.Information);
            break;
          case "Google":
            _utilityService.InsertLogEntry(HttpContext, "Google Login", message, LogType.Information);
            break;
          case "Microsoft":
            _utilityService.InsertLogEntry(HttpContext, "Microsoft Login", message, LogType.Information);
            break;
          case "Twitter":
            _utilityService.InsertLogEntry(HttpContext, "Twitter Login", message, LogType.Information);
            break;
          default:
            _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login", message, LogType.Information);
            break;
        }
        return RedirectToLocal(returnUrl);
      }
      if (result.RequiresTwoFactor)
      {
        _utilityService.InsertLogEntry(HttpContext, "Two Factor Required", info.LoginProvider +
          " login requires two factor verification.", LogType.Information);
        return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl });
      }
      if (result.IsLockedOut)
      {
        _utilityService.InsertLogEntry(HttpContext, "Login Lockout", info.LoginProvider + " login is locked out.",
          LogType.Error, true);
        return View("Lockout");
      }
      else
      {
        // If the user does not have an account, then ask the user to create an account.
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["LoginProvider"] = info.LoginProvider;
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var infomessage = $"ExternalLoginCallback post login with no account.";
        switch (info.LoginProvider)
        {
          case "Facebook":
            _utilityService.InsertLogEntry(HttpContext, "Facebook Login Account None", infomessage, LogType.Information);
            break;
          case "GitHub":
            _utilityService.InsertLogEntry(HttpContext, "GitHub Login Account None", infomessage, LogType.Information);
            break;
          case "Google":
            _utilityService.InsertLogEntry(HttpContext, "Google Login Account None", infomessage, LogType.Information);
            break;
          case "Microsoft":
            _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Account None", infomessage, LogType.Information);
            break;
          case "Twitter":
            _utilityService.InsertLogEntry(HttpContext, "Twitter Login Account None", infomessage, LogType.Information);
            break;
          default:
            _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Account None", infomessage,
              LogType.Information);
            break;
        }
        return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });
      }
    }

    //
    // POST: /Account/ExternalLoginConfirmation
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model,
      string returnUrl = null)
    {
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "External Login Error", "ExternalLoginConfirmation post model state is invalid.",
          LogType.Error, true);
        return View(model);
      }
      // Get the information about the user from the external login provider
      var info = await _signInManager.GetExternalLoginInfoAsync();
      if (info == null)
      {
        _utilityService.InsertLogEntry(HttpContext, "External Login Error", "ExternalLoginConfirmation post info is null.",
          LogType.Error, true);
        return View("ExternalLoginFailure");
      }
      var user = new ApplicationUser { UserName = model.UserName, Email = model.Email };
      var result = await _userManager.CreateAsync(user);
      if (result.Succeeded)
      {
        result = await _userManager.AddLoginAsync(user, info);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          var message = $"User created an account using {info.LoginProvider} provider.";
          switch (info.LoginProvider)
          {
            case "Facebook":
              _utilityService.InsertLogEntry(HttpContext, "Facebook Login Account Registered", message, LogType.Information, true);
              break;
            case "GitHub":
              _utilityService.InsertLogEntry(HttpContext, "GitHub Login Account Registered", message, LogType.Information, true);
              break;
            case "Google":
              _utilityService.InsertLogEntry(HttpContext, "Google Login Account Registered", message, LogType.Information, true);
              break;
            case "Microsoft":
              _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Account Registered", message, LogType.Information, true);
              break;
            case "Twitter":
              _utilityService.InsertLogEntry(HttpContext, "Twitter Login Account Registered", message, LogType.Information, true);
              break;
            default:
              _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Account Registered", message,
                LogType.Information, true);
              break;
          }
          return RedirectToLocal(returnUrl);
        }
      }
      var err = AddErrors(result);
      var errormessage = $"User failed creating an account using {info.LoginProvider} provider. result = " + err;
      switch (info.LoginProvider)
      {
        case "Facebook":
          _utilityService.InsertLogEntry(HttpContext, "Facebook Login Error", errormessage, LogType.Error, true);
          break;
        case "GitHub":
          _utilityService.InsertLogEntry(HttpContext, "GitHub Login Error", errormessage, LogType.Error, true);
          break;
        case "Google":
          _utilityService.InsertLogEntry(HttpContext, "Google Login Error", errormessage, LogType.Error, true);
          break;
        case "Microsoft":
          _utilityService.InsertLogEntry(HttpContext, "Microsoft Login Error", errormessage, LogType.Error, true);
          break;
        case "Twitter":
          _utilityService.InsertLogEntry(HttpContext, "Twitter Login Error", errormessage, LogType.Error, true);
          break;
        default:
          _utilityService.InsertLogEntry(HttpContext, info.LoginProvider + " Login Error", errormessage, LogType.Error, true);
          break;
      }

      ViewData["ReturnUrl"] = returnUrl;
      return View(model);
    }

    // GET: /Account/ConfirmEmail
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
      _utilityService.SetViewCookie(HttpContext, "Confirm Email View", "ConfirmEmailView", LogType.Information);
      if (userId == null || code == null)
      {
        _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Error", "ConfirmEmail userId or code is null.",
          LogType.Error, true);
        return View("Error");
      }
      var user = await _userManager.FindByIdAsync(userId);
      if (user == null)
      {
        _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Error", "ConfirmEmail user not found.", LogType.Error, true);
        return View("Error");
      }
      var result = await _userManager.ConfirmEmailAsync(user, code);
      if (result.Succeeded)
      {
        _utilityService.InsertLogEntry(HttpContext, "Email Confirmed", "User successfully confirmed email.", LogType.Information);
        return View("ConfirmEmail");
      }
      _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Error", "ConfirmEmail unknown error.", LogType.Error, true);
      return View("Error");
    }

    //
    // GET: /Account/ForgotPassword
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
      _utilityService.SetViewCookie(HttpContext, "Forgot Password View", "ForgotPasswordView", LogType.Information);
      return View();
    }

    //
    // POST: /Account/ForgotPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Forgot Password Error", "ForgotPassword post model state is invalid.",
          LogType.Error, true);
        return View(model);
      }
      var user = await _userManager.FindByEmailAsync(model.Email);
      if (user == null)
      {
        // Do reveal that the user does not exist redirect to Register
        _utilityService.InsertLogEntry(HttpContext, "Forgot Password Error", "ForgotPassword post user not found.",
          LogType.Error, true);
        return RedirectToAction(nameof(AccountController.Register), "Account");
      }
      if (!(await _userManager.IsEmailConfirmedAsync(user)))
      {
        // Don't reveal that the user email is not confirmed
        _utilityService.InsertLogEntry(HttpContext, "Forgot Password Error", user.UserName + " - ForgotPassword post user email" +
              " not confirmed.", LogType.Error, true);
        return View("ForgotPasswordConfirmation");
      }
      var code = await _userManager.GeneratePasswordResetTokenAsync(user);
      var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code },
        protocol: HttpContext.Request.Scheme);
      var sb = new StringBuilder("<html><body><div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>" +
              "Reset Password for " + _settings.Name);
      sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
      sb.Append(user.UserName);
      sb.Append(",<br/>Please click <a href='");
      sb.Append(callbackUrl);
      sb.Append("'>here</a> to reset your password for " + _settings.Name + ".<br/><br/>If you have any problem, please let me" +
              " know.<br/>");
      sb.Append("Email  <a href='mailto:" + _settings.SupportEmail + "?subject=Reset Password'>" + _settings.SupportEmail +
        "</a><br/><br/>Thank you,<br/>" + _settings.SupportName + "<br/><br/>");
      sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

      //await _emailSender.SendEmailAsync(model.Email, "Reset Password", sb.ToString());
      await Task.Run(() => { Task.Delay(500); });

      _utilityService.InsertLogEntry(HttpContext, "Forgot Password Sent", "User sent forgot password email.", LogType.Information);
      return View("ForgotPasswordConfirmation");
    }

    //
    // GET: /Account/ForgotPasswordConfirmation
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
      _utilityService.SetViewCookie(HttpContext, "Forgot Password Confirmation View", "ForgotPasswordConfirmationView",
        LogType.Information);
      return View();
    }

    //
    // GET: /Account/VerifyEmail
    [HttpGet]
    [AllowAnonymous]
    public IActionResult VerifyEmail(string username = null)
    {
      _utilityService.SetViewCookie(HttpContext, "Verify Email View", "VerifyEmailView", LogType.Information);
      return View(new VerifyEmailViewModel { UserName = username });
    }

    //
    // POST: /Account/VerifyEmail
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyEmail(VerifyEmailViewModel model)
    {
      ViewData["Theme"] = Request.Cookies["TempThemeCookie"];
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Error", "VerifyEmail post model state is invalid.",
          LogType.Error, true);
        return View(model);
      }
      var user = await _userManager.FindByEmailAsync(model.Email);
      if (user == null)
      {
        // Don't reveal that the email does not exist
        _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Error", "VerifyEmail post user not found.",
          LogType.Error, true);
        return View("VerifyEmailConfirmation");
      }
      else if (user.UserName.ToLower() != model.UserName.ToLower())
      {
        // Don't reveal that the email does not match
        _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Error", "VerifyEmail post username does not match.",
          LogType.Error, true);
        return View("VerifyEmailConfirmation");
      }
      else
      {
        // For more information on how to enable account confirmation and password reset please visit 
        //  http://go.microsoft.com/fwlink/?LinkID=532713
        // Send an email with this link
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code },
          protocol: HttpContext.Request.Scheme);
        var sb = new StringBuilder("<html><body><div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>" +
              "Email Verification for " + _settings.Name);
        sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
        sb.Append(user.UserName);
        sb.Append(",<br/>Thank you for your interest. Please click <a href='");
        sb.Append(callbackUrl);
        sb.Append("'>here</a> to verify your email.<br/> You must verify your email before you log in to " + _settings.Name +
          ".<br/><br/>If you have any problem, please let me know.<br/>");
        sb.Append("Email  <a href='mailto:" + _settings.SupportEmail + "?subject=Verify Email'>" + _settings.SupportEmail +
          "</a><br/><br/>Thank you again,<br/>" + _settings.SupportName + "<br/><br/>");
        sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

        //await _emailSender.SendEmailAsync(model.Email, "Email Verification for " + _settings.Name, sb.ToString());
        await Task.Run(() => { Task.Delay(500); });

        _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Sent", "User sent verify email.", LogType.Information);
        return View("VerifyEmailConfirmation");
      }
    }


    //
    // GET: /Account/ResetPassword
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string code = null)
    {
      _utilityService.SetViewCookie(HttpContext, "Password Reset View", "PasswordResetView", LogType.Information);
      return code == null ? View("Error") : View();
    }

    //
    // POST: /Account/ResetPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }
      var user = await _userManager.FindByEmailAsync(model.Email);
      if (user == null)
      {
        // Don't reveal that the user does not exist
        _utilityService.InsertLogEntry(HttpContext, "Password Reset Error", "ResetPassword post user not found.", LogType.Error, true);
        return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
      }
      var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
      if (result.Succeeded)
      {
        _utilityService.InsertLogEntry(HttpContext, "Password Reset Sucess", "User successfully reset password.", LogType.Information);
        return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
      }
      AddErrors(result);
      return View();
    }

    //
    // GET: /Account/ResetPasswordConfirmation
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
      _utilityService.SetViewCookie(HttpContext, "Password Reset Confirmation View", "PasswordResetConfirmationView",
        LogType.Information);
      return View();
    }

    //
    // GET: /Account/SendCode
    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
    {
      _utilityService.SetViewCookie(HttpContext, "Two Factor Send Code View", "TwoFactorSendCodeView", LogType.Information);
      var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
      var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
      return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
    }

    //
    // POST: /Account/SendCode
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendCode(SendCodeViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View();
      }

      var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
      if (user == null)
      {
        return View("Error");
      }

      // Generate the token and send it
      var code = await _userManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);
      if (string.IsNullOrWhiteSpace(code))
      {
        return View("Error");
      }

      //var message = "Your security code is: " + code;
      var message = $"Your verify code for { _settings.Name } is: {code}";
      if (model.SelectedProvider == "Email")
      {

        //await _emailSender.SendEmailAsync(await _userManager.GetEmailAsync(user), "Security Code", message);
        await Task.Run(() => { Task.Delay(500); });

        _utilityService.InsertLogEntry(HttpContext, "Two Factor Send Email", "User sent code to email.", LogType.Information);
      }
      else if (model.SelectedProvider == "Phone")
      {

        //await _smsSender.SendSmsAsync(await _userManager.GetPhoneNumberAsync(user), message);
        await Task.Run(() => { Task.Delay(500); });

        _utilityService.InsertLogEntry(HttpContext, "Two Factor Send Code", "User sent code to phone.", LogType.Information);
      }

      return RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider,
        ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
    }

    //
    // GET: /Account/VerifyCode
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
    {
      _utilityService.SetViewCookie(HttpContext, "Two Factor Verify Code View", "TwoFactorVerifyCodeView", LogType.Information);
      // Require that the user has already logged in via username/password or external login
      var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
      if (user == null)
      {
        return View("Error");
      }
      return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
    }

    //
    // POST: /Account/VerifyCode
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
    {
      if (!ModelState.IsValid)
      {
        return View(model);
      }

      // The following code protects for brute force attacks against the two factor codes.
      // If a user enters incorrect codes for a specified amount of time then the user account
      // will be locked out for a specified amount of time.
      var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe,
        model.RememberBrowser);
      if (result.Succeeded)
      {
        _utilityService.InsertLogEntry(HttpContext, "Two Factor Logged In", "User logged in with two factors.", LogType.Information);
        return RedirectToLocal(model.ReturnUrl);
      }
      if (result.IsLockedOut)
      {
        //_logger.LogWarning(7, "User account locked out.");
        _utilityService.InsertLogEntry(HttpContext, "Two Factor Login Lockout", "User account locked out.", LogType.Error, true);
        return View("Lockout");
      }
      else
      {
        ModelState.AddModelError(string.Empty, "Invalid code.");
        return View(model);
      }
    }

    //
    // GET /Account/AccessDenied
    [HttpGet]
    public IActionResult AccessDenied()
    {
      return View();
    }

    #region Helpers

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

    private Task<ApplicationUser> GetCurrentUserAsync()
    {
      return _userManager.GetUserAsync(HttpContext.User);
    }

    private IActionResult RedirectToLocal(string returnUrl)
    {
      if (Url.IsLocalUrl(returnUrl))
      {
        return Redirect(returnUrl);
      }
      else
      {
        return RedirectToAction(nameof(HomeController.Index), "Home");
      }
    }

    #endregion
  }
}
