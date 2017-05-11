using MVC.Data;
using MVC.Models;
using MVC.Models.AdminViewModels;
using MVC.Models.SettingsModels;
using MVC.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace MVC.Controllers
{
  [Authorize(Roles = "AdminRole, LogViewRole, ManagerRole")]
  public class AdminController : Controller
  {
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly IEmailSender _emailSender;
    private readonly ISmsSender _smsSender;
    private readonly IUtilityService _utilityService;
    private readonly Settings _settings;
    private readonly LogDbContext _logcontext;

    public AdminController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<ApplicationRole> roleManager,
        IEmailSender emailSender,
        ISmsSender smsSender,
        IUtilityService utilityService,
        IOptionsSnapshot<Settings> settings,
        LogDbContext logcontext)
    {
      _userManager = userManager;
      _signInManager = signInManager;
      _roleManager = roleManager;
      _emailSender = emailSender;
      _smsSender = smsSender;
      _utilityService = utilityService;
      _settings = settings.Value;
      _logcontext = logcontext;
    }

    //
    // GET: /Admin/LogEntries
    [HttpGet]
    [Authorize(Roles = "AdminRole, LogViewRole")]
    public async Task<ActionResult> LogEntries(int? Page, string Start = "", string End = "", LogType Type = LogType.All, string Country = "Recent Countries")
    {
      _utilityService.SetViewCookie(HttpContext, "Log Entries View", "LogEntriesView", LogType.Information);
      var tzoffset = 0;
      if (Request.Cookies != null && Request.Cookies.Count > 0)
      {
        if (Request.Cookies["tzoffset"] != null)
        {
          tzoffset = Int32.Parse(Request.Cookies["tzoffset"]);
        }
      }
      DateTime startdate;
      DateTime enddate;
      if (Start.Length == 0 || !IsDatePicker(Start))
      {
        startdate = DateTime.UtcNow;
        var smin = startdate.Minute % 15;
        smin *= -1;
        startdate = startdate.AddDays(-7).AddMinutes(smin);
        Start = startdate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm zzz");
      }
      else
      {
        startdate = DateTime.ParseExact(Start, "yyyy-MM-dd HH:mm zzz", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime();
      }
      if (End.Length == 0 || !IsDatePicker(End))
      {
        enddate = DateTime.UtcNow;
        var emin = 15 - enddate.Minute % 15; // + 30;
        enddate = enddate.AddMinutes(emin);
        End = enddate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm zzz");
      }
      else
      {
        enddate = DateTime.ParseExact(End, "yyyy-MM-dd HH:mm zzz", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime();
      }

      var itemsPerPage = 10;
      var pageNumber = Page ?? 1;
      var alltypes = Enum.GetValues(typeof(LogType)).Cast<LogType>().ToArray();
      var typelist = from value in alltypes
                     select new SelectListItem()
                     {
                       Value = ((int)value).ToString(),
                       Text = value.ToString()
                     };

      var selectlist = new List<SelectListItem>(typelist);

      var v = new LogEntriesViewModel();
      try
      {
        var entries = _logcontext.LogEntries.Where(e => e.CreateDate > startdate && e.CreateDate < enddate).AsQueryable();
        if (Type != LogType.All)
        {
          entries = entries.Where(e => e.LogType == Type);
        }
        entries = entries.OrderByDescending(e => e.CreateDate).Take(1000).AsQueryable();
        v.TZoffset = tzoffset;
        v.PageIndex = pageNumber;
        v.RowIndex = itemsPerPage * pageNumber - itemsPerPage + 1;
        var count = await entries.CountAsync();
        v.EntryCount = count;
        v.TotalPages = (int)Math.Ceiling(count / (double)itemsPerPage);
        v.StartDate = Start;
        v.EndDate = End;
        v.Type = Type;
        v.Country = Country;
        v.Types = selectlist;
        v.Entries = await entries.AsNoTracking().Skip((pageNumber - 1) * itemsPerPage).Take(itemsPerPage).ToListAsync();
      }
      catch (Exception ex)
      {
        _utilityService.InsertLogEntry(HttpContext, "LogDbContext Error", "LogEntries threw an exception.", LogType.Critical, true, ex);
        throw;
      }
      return View(v);
    }

    //
    // AJAX GET: /Admin/LogEntry
    // Called by AJAX must return JSON
    [HttpGet]
    [Authorize(Roles = "AdminRole, LogViewRole")]
    public JsonResult LogEntry(string id = "")
    {
      if (id != string.Empty)
      {
        try
        {
          var entry = _logcontext.LogEntries.Where(e => e.ID == id).FirstOrDefault();
          return Json(entry);
        }
        catch (Exception ex)
        {
          _utilityService.InsertLogEntry(HttpContext, "LogDbContext Error", "LogEntry threw an exception.", LogType.Critical, true, ex);
          return Json(new { error = "LogDbContext Exception." });
        }
      }
      else
      {
        _utilityService.InsertLogEntry(HttpContext, "LogEntry Error", "Id is empty.", LogType.Critical, true);
        return Json(new { error = "Id is empty." });
      }
    }

    //
    // GET: /Admin/ControlPanel
    [HttpGet]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    public async Task<IActionResult> ControlPanel()
    {
      _utilityService.SetViewCookie(HttpContext, "Control Panel View", "ControlPanelView", LogType.Information);
      // for testing
      //await _smsSender.SendSmsAsync("+19876543210", "Test of Asp.Net Core Twilio.");
      //await _emailSender.SendEmailAsync("You@YourDomain.Com", "Test Email.", "Test of Asp.Net Core Email.");            
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        ModelState.AddModelError("", "The current user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Error", "ControlPanel current user was not found.", LogType.Error, true);
        return View();
      }

      try
      {
        var hostName = Dns.GetHostName();
        ViewBag.ServerHost = "Server: HostName = " + hostName;
        var remoteip = HttpContext.Request.HttpContext.Connection.RemoteIpAddress.ToString();
        var sb = new StringBuilder("RemoteIP = " + remoteip + ", IPs = ");
        var hostIPs = await Dns.GetHostAddressesAsync(hostName);
        foreach (var ip in hostIPs)
        {
          sb.Append(ip + ", ");
        }
        ViewBag.RemoteIPs = sb.ToString();
      }
      catch (Exception ex)
      {
        ViewBag.ServerHost = "DNS exception = " + ex.Message;
      }
      var version = Assembly.GetEntryAssembly().GetName().Version.ToString();
      ViewBag.Version = $"Version {version}";
      ViewBag.Description = "Admin - ControlPanel description.";
      var users = _userManager.Users;
      var ul = new List<UserViewModel>();
      foreach (ApplicationUser u in users)
      {
        var uroles = await _userManager.GetRolesAsync(u);
        var list = uroles.OrderBy(q => q).ToList();
        var userModel = new UserViewModel(u, list);
        ul.Add(userModel);
      }
      return View(ul);
    }

    //
    // POST: /Admin/ControlPanel
    [HttpPost]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ControlPanel(string id = "")
    {

      var users = _userManager.Users;
      var ul = new List<UserViewModel>();
      foreach (ApplicationUser u in users)
      {
        var uroles = await _userManager.GetRolesAsync(u);
        var list = uroles.OrderBy(q => q).ToList();
        var userModel = new UserViewModel(u, list);
        ul.Add(userModel);
      }
      return View(ul);

    }

    //
    // GET: /Admin/UserIndex
    [HttpGet]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    public async Task<IActionResult> UserIndex()
    {
      _utilityService.SetViewCookie(HttpContext, "User Index View", "UserIndexView", LogType.Information);
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        ModelState.AddModelError("", "The current user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "UserIndex current user was not found.", LogType.Error, true);
        return View();
      }
      var users = _userManager.Users;
      var ul = new List<UserViewModel>();
      foreach (ApplicationUser u in users)
      {
        var uroles = await _userManager.GetRolesAsync(u);
        if (!await _userManager.IsInRoleAsync(user, "AdminRole"))
        {
          if (uroles.Contains("AdminRole"))
          {
            continue;
          }
        }
        var list = uroles.OrderBy(q => q).ToList();
        var userLogins = await _userManager.GetLoginsAsync(u);
        var exlogins = "";
        foreach (UserLoginInfo el in userLogins)
        {
          exlogins += el.LoginProvider[0] + ",";
        }
        var userModel = new UserViewModel(u, list, exlogins);
        ul.Add(userModel);
      }
      return View(ul);
    }

    //
    // GET: /Admin/UserRoles
    [HttpGet]
    [Authorize(Roles = "AdminRole")]
    public async Task<IActionResult> UserRoles(string id = "")
    {
      _utilityService.SetViewCookie(HttpContext, "User Roles View", "UserRolesView", LogType.Information);
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "UserRoles id is null or empty.", LogType.Error, true);
        return View();
      }
      var user = await _userManager.FindByNameAsync(id);
      if (user == null)
      {
        ModelState.AddModelError("", "The user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "UserRoles user was not found.", LogType.Error, true);
        return View();
      }
      var uroles = await _userManager.GetRolesAsync(user);
      //Add all available roles to the list of EditorViewModels:
      var allRoles = _roleManager.Roles.OrderBy(r => r.Name);
      var rolesView = new List<RoleViewModel>();
      foreach (ApplicationRole r in allRoles)
      {
        var rvm = new RoleViewModel(r);
        if (uroles.Contains(r.Name))
        {
          rvm.Selected = true;
        }
        rolesView.Add(rvm);
      }
      ViewBag.UserName = user.UserName;
      return View(rolesView);
    }

    //
    // POST: /Admin/SetUserRole
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "AdminRole")]
    public async Task<IActionResult> SetUserRole(string id, string role)
    {
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Role Error", "SetUserRole post id is null or empty.", LogType.Error, true);
        return View("UserRoles");
      }
      var user = await _userManager.FindByNameAsync(id);
      if (user == null)
      {
        ModelState.AddModelError("", "The user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Role Error", "SetUserRole post current user was not found.", LogType.Error, true);
        return View("UserRoles");
      }

      string r = HttpContext.Request.Form[role];
      if (r == null)
      {
        await _userManager.RemoveFromRoleAsync(user, role);
        _utilityService.InsertLogEntry(HttpContext, "Remove From Role", "The user " + user + " was removed from " + role + ".", LogType.Information);
      }
      else
      {
        await _userManager.AddToRoleAsync(user, role);
        _utilityService.InsertLogEntry(HttpContext, "Add To Role", "The user " + user + " was added to " + role + ".", LogType.Information);
      }
      return RedirectToAction("UserRoles", "Admin", new RouteValueDictionary(new { id = id }));
    }

    //
    // GET: Admin/NewUser
    [HttpGet]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    public IActionResult NewUser()
    {
      _utilityService.SetViewCookie(HttpContext, "New User View", "NewUserView", LogType.Information);
      return View();
    }

    //
    // POST: Admin/NewUser
    [HttpPost]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> NewUser([Bind("UserName,Email,EmailConfirmed,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,Password,MustChangePassword,SendWelcome")] UserViewModel model)
    {
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "NewUser post model state is invalid.", LogType.Error, true);
        return View(model);
      }
      if (ModelState.IsValid)
      {
        if (string.IsNullOrEmpty(model.PhoneNumber))
        {
          model.PhoneNumberConfirmed = false;
        }
        else if (model.PhoneNumber.Length < 8 && model.PhoneNumberConfirmed)
        {
          model.PhoneNumberConfirmed = false;
        }
        var user = new ApplicationUser
        {
          UserName = model.UserName,
          Email = model.Email,
          EmailConfirmed = model.EmailConfirmed,
          PhoneNumber = model.PhoneNumber,
          PhoneNumberConfirmed = model.PhoneNumberConfirmed
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
          if (!user.EmailConfirmed)
          {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
            var sb = new StringBuilder("<html><body><div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>Email Verification for " + _settings.Name);
            sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
            sb.Append("Your administrator created a new user for this email address.<br/><br/>");
            sb.Append("Your Login Name:&nbsp;");
            sb.Append(user.UserName);
            sb.Append("<br/>Your Password:&nbsp;");
            sb.Append(model.Password);
            sb.Append("<br/><br/>Please click <a href='");
            sb.Append(callbackUrl);
            sb.Append("'>here</a> to verify your email.<br/> You must verify your email before you log in to " + _settings.Name + ".<br/><br/>If you have any problem, please let me know.<br/>");
            sb.Append("Email  <a href='mailto:" + _settings.SupportEmail + "?subject=Verify Email'>" + _settings.SupportEmail + "</a><br/><br/>Thank you again,<br/>" + _settings.SupportName + "<br/><br/>");
            sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

            //await _emailSender.SendEmailAsync(model.Email, "Email Verification for " + _settings.Name, sb.ToString());
            await Task.Run(() => { Task.Delay(500); });

            _utilityService.InsertLogEntry(HttpContext, "Email Confirmation Sent", user.UserName + " was sent the confirmation email.", LogType.Information);
          }
          else
          {
            if (model.SendWelcome)
            {
              var callbackUrl = Url.Action("Login", "Account", null, protocol: HttpContext.Request.Scheme);
              var sb = new StringBuilder("<html><body><div style='font-weight: bold; font-size: 24pt; font-family: Tahoma;'>Welcome to " + _settings.Name);
              sb.Append("</div><br/><div style='font-weight: normal; font-size: 14pt; font-family: Tahoma;'>");
              sb.Append("Your administrator created a new user for this email address.<br/><br/>");
              sb.Append("Your Login Name:&nbsp;");
              sb.Append(user.UserName);
              sb.Append("<br/>Your Password:&nbsp;");
              sb.Append(model.Password);
              if (model.MustChangePassword)
              {
                sb.Append("<br/>You must change your password at first login.");
              }
              sb.Append("<br/><br/>Please click <a href='");
              sb.Append(callbackUrl);
              sb.Append("'>here</a> to login.<br/><br/>If you have any problem, please let me know.<br/>");
              sb.Append("Email  <a href='mailto:" + _settings.SupportEmail + "?subject=Welcome Email'>" + _settings.SupportEmail + "</a><br/><br/>Thank you again,<br/>" + _settings.SupportName + "<br/><br/>");
              sb.Append("THIS IS AN AUTOMATED MESSAGE.</div></body></html>");

              //await _emailSender.SendEmailAsync(model.Email, "Welcome to " + _settings.Name, sb.ToString());
              await Task.Run(() => { Task.Delay(500); });

              _utilityService.InsertLogEntry(HttpContext, "Email Welcome Sent", user.UserName + " was sent the welcome email.", LogType.Information);
            }
          }
          _utilityService.InsertLogEntry(HttpContext, "Admin User Added", "Admin created a new account with password.", LogType.Information);
          return RedirectToAction("UserIndex");
        }
        var err = AddErrors(result);
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "NewUser post result = " + err, LogType.Error, true);
      }
      return View();
    }

    //
    // GET: Admin/EditUser
    [HttpGet]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    public async Task<IActionResult> EditUser(string id = "")
    {
      _utilityService.SetViewCookie(HttpContext, "Edit User View", "EditUserView", LogType.Information);
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "EditUser id is null or empty.", LogType.Error, true);
        return View();
      }
      var user = await _userManager.FindByNameAsync(id);
      if (user == null)
      {
        ModelState.AddModelError("", "The user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "EditUser Error", "EditUser user was not found.", LogType.Error, true);
        return View();
      }
      var roles = await _userManager.GetRolesAsync(user);
      var list = roles.OrderBy(q => q).ToList();
      var userLogins = await _userManager.GetLoginsAsync(user);
      var exlogins = "";
      foreach (UserLoginInfo el in userLogins)
      {
        exlogins += el.LoginProvider[0] + ",";
      }
      var usermodel = new EditUserViewModel(user, list, exlogins);
      return View(usermodel);
    }

    //
    // POST: Admin/EditUser
    [HttpPost]
    [Authorize(Roles = "AdminRole, ManagerRole")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditUser(EditUserViewModel model)
    {
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "EditUser post model state is invalid.", LogType.Error, true);
        return View(model);
      }
      if (ModelState.IsValid)
      {
        if (model.PhoneNumber != null && model.PhoneNumber.Length < 10 && model.PhoneNumberConfirmed)
        {
          model.PhoneNumberConfirmed = false;
        }
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user == null)
        {
          ModelState.AddModelError("", "The user was not found.");
          _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "EditUser post user was not found.", LogType.Error, true);
          return View(model);
        }
        if (model.Password != null)
        {
          var token = await _userManager.GeneratePasswordResetTokenAsync(user);
          var resetresult = await _userManager.ResetPasswordAsync(user, token, model.Password);
          if (!resetresult.Succeeded)
          {
            var err = AddErrors(resetresult);
            _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "EditUser post result = " + err, LogType.Error, true);
            return View(model);
          }
        }
        user.Email = model.Email;
        user.EmailConfirmed = model.EmailConfirmed;
        user.PhoneNumber = model.PhoneNumber;
        user.PhoneNumberConfirmed = model.PhoneNumberConfirmed;
        user.TwoFactorEnabled = model.TwoFactorEnabled;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
          var err = AddErrors(result);
          _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "EditUser post result = " + err, LogType.Error, true);
          return View(model);
        }
        else
        {
          _utilityService.InsertLogEntry(HttpContext, "Admin User Updated", user.UserName + " was updated by admin.", LogType.Information);
        }
        return RedirectToAction("UserIndex");
      }
      return View();
    }

    //
    // GET: Admin/DeleteUser
    [HttpGet]
    [Authorize(Roles = "AdminRole")]
    public async Task<IActionResult> DeleteUser(string id = "")
    {
      _utilityService.SetViewCookie(HttpContext, "Delete User View", "DeleteUserView", LogType.Information);
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "DeleteUser id is null or empty.", LogType.Error, true);
        return View();
      }
      var user = await _userManager.FindByNameAsync(id);
      if (user == null)
      {
        ModelState.AddModelError("", "The user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "DeleteUser user was not found.", LogType.Error, true);
        return View();
      }
      var uroles = await _userManager.GetRolesAsync(user);
      var list = uroles.OrderBy(q => q).ToList();
      var model = new UserViewModel(user, list);
      return View(model);

    }

    //
    // POST: Admin/DeleteUser
    [HttpPost]
    [Authorize(Roles = "AdminRole")]
    [ActionName("DeleteUser")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteUserConfirmed(string id = "")
    {
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "DeleteUserConfirmed post id is null or empty.", LogType.Error, true);
        return View();
      }
      var user = await _userManager.FindByNameAsync(id);
      if (user == null)
      {
        ModelState.AddModelError("", "The user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "DeleteUserConfirmed post user was not found.", LogType.Error, true);
        return View();
      }
      var result = await _userManager.DeleteAsync(user);
      if (!result.Succeeded)
      {
        var err = AddErrors(result);
        _utilityService.InsertLogEntry(HttpContext, "Admin User Error", "DeleteUserConfirmed post result = " + err, LogType.Error, true);
        return View();
      }
      else
      {
        _utilityService.InsertLogEntry(HttpContext, "Admin User Deleted", user.UserName + " was deleted by admin.", LogType.Information);
      }
      return RedirectToAction("UserIndex");
    }

    //
    // GET: /Admin/RoleIndex
    [HttpGet]
    [Authorize(Roles = "AdminRole")]
    public async Task<IActionResult> RoleIndex()
    {
      _utilityService.SetViewCookie(HttpContext, "Role Index View", "RoleIndexView", LogType.Information);
      var user = await GetCurrentUserAsync();
      if (user == null)
      {
        ModelState.AddModelError("", "The current user was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "RoleIndex current user was not found.", LogType.Error, true);
        return View();
      }
      var roles = await _userManager.GetRolesAsync(user);
      var list = roles.OrderBy(q => q).ToList();
      var rs = string.Empty;
      foreach (var r in list)
      {
        rs += r + ',';
      }
      var rolesList = new List<RoleViewModel>();
      var allroles = _roleManager.Roles.OrderBy(r => r.Name);
      foreach (ApplicationRole r in allroles)
      {
        var roleModel = new RoleViewModel(r);
        rolesList.Add(roleModel);
      }
      return View(rolesList);
    }

    //
    // GET: Admin/NewRole
    [HttpGet]
    [Authorize(Roles = "AdminRole")]
    public IActionResult NewRole()
    {
      _utilityService.SetViewCookie(HttpContext, "New Role View", "NewRoleView", LogType.Information);
      return View();
    }

    //
    // POST: Admin/NewRole
    [HttpPost]
    [Authorize(Roles = "AdminRole")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> NewRole([Bind("Name,Description")] RoleViewModel model)
    {
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "NewRole post model state is invalid.", LogType.Error, true);
        return View(model);
      }
      if (ModelState.IsValid)
      {
        if (await _roleManager.RoleExistsAsync(model.Name))
        {
          ModelState.AddModelError("", "The role name " + model.Name + " has already been used.");
          _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "NewRole post role name " + model.Name + " has already been used.", LogType.Error, true);
          return View(model);
        }
        else
        {
          var roleResult = await _roleManager.CreateAsync(new ApplicationRole(model.Name, model.Description));
          if (!roleResult.Succeeded)
          {
            var err = AddErrors(roleResult);
            _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "NewRole post result = " + err, LogType.Error, true);
            return View(model);
          }
          else
          {
            _utilityService.InsertLogEntry(HttpContext, "Admin Role Added", model.Name + " was added by admin.", LogType.Information);
          }
          return RedirectToAction("RoleIndex");
        }
      }
      return View();
    }

    //
    // GET: Admin/EditRole
    [HttpGet]
    [Authorize(Roles = "AdminRole")]
    public async Task<IActionResult> EditRole(string id = "")
    {
      _utilityService.SetViewCookie(HttpContext, "Edit Role View", "EditRoleView", LogType.Information);
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "EditRole id is null or empty.", LogType.Error, true);
        return View();
      }
      var role = await _roleManager.FindByNameAsync(id);
      if (role == null)
      {
        ModelState.AddModelError("", "The role was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "EditRole role was not found.", LogType.Error, true);
        return View();
      }
      var rolemodel = new RoleViewModel(role);
      return View(rolemodel);

    }

    //
    // POST: Admin/EditRole
    [HttpPost]
    [Authorize(Roles = "AdminRole")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditRole(RoleViewModel model)
    {
      if (!ModelState.IsValid)
      {
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "EditRole post model state is invalid.", LogType.Error, true);
        return View(model);
      }
      if (ModelState.IsValid)
      {
        var role = await _roleManager.FindByNameAsync(model.Name);
        if (role == null)
        {
          ModelState.AddModelError("", "The role was not found.");
          _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "EditRole post role was not found.", LogType.Error, true);
          return View();
        }
        var roleResult = await _roleManager.UpdateAsync(role);
        if (!roleResult.Succeeded)
        {
          var err = AddErrors(roleResult);
          _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "EditRole post result = " + err, LogType.Error, true);
          return View(model);
        }
        else
        {
          _utilityService.InsertLogEntry(HttpContext, "Admin Role Updated", model.Name + " was updated by admin.", LogType.Information);
        }
        return RedirectToAction("RoleIndex");
      }
      return View();
    }

    //
    // GET: Admin/DeleteRole
    [HttpGet]
    [Authorize(Roles = "AdminRole")]
    public async Task<IActionResult> DeleteRole(string id = "")
    {
      _utilityService.SetViewCookie(HttpContext, "Delete Role View", "DeleteRoleView", LogType.Information);
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "DeleteRole id is null or empty.", LogType.Error, true);
        return View();
      }
      var role = await _roleManager.FindByNameAsync(id);
      if (role == null)
      {
        ModelState.AddModelError("", "The role was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "DeleteRole role was not found.", LogType.Error, true);
        return View();
      }
      var model = new RoleViewModel(role);
      return View(model);
    }

    //
    // POST: Admin/DeleteRole
    [HttpPost]
    [Authorize(Roles = "AdminRole")]
    [ActionName("DeleteRole")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteRoleConfirmed(string id = "")
    {
      if (string.IsNullOrEmpty(id) == true)
      {
        ModelState.AddModelError("", "The id is null or empty.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "DeleteRoleConfirmed post id is null or empty.", LogType.Error, true);

        return View();
      }
      var role = await _roleManager.FindByNameAsync(id);
      if (role == null)
      {
        ModelState.AddModelError("", "The role was not found.");
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "DeleteRoleConfirmed post role was not found.", LogType.Error, true);
        return View();
      }
      var roleResult = await _roleManager.DeleteAsync(role);
      if (!roleResult.Succeeded)
      {
        var err = AddErrors(roleResult);
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Error", "DeleteRoleConfirmed post result = " + err, LogType.Error, true);
        return View();
      }
      else
      {
        _utilityService.InsertLogEntry(HttpContext, "Admin Role Deleted", id + " was deleted by admin.", LogType.Information);
      }
      return RedirectToAction("RoleIndex");
    }

    #region Helpers

    private bool IsDatePicker(string dateString)
    {
      string utcformat = "yyyy-MM-dd HH:mm zzz";
      if (DateTime.TryParseExact(dateString, utcformat, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime dateTime))
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

    private Task<ApplicationUser> GetCurrentUserAsync()
    {
      return _userManager.GetUserAsync(HttpContext.User);
    }

    #endregion
  }
}