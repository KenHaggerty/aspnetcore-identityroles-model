using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MVC.Data;
using MVC.Models;
using MVC.Models.SettingsModels;
using MVC.Services;
using Newtonsoft.Json.Serialization;
using System;
using System.IO;
using System.Reflection;

namespace MVC
{
  public class Startup
  {
    public Startup(IHostingEnvironment env)
    {
      var builder = new ConfigurationBuilder()
          .SetBasePath(env.ContentRootPath)
          .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
          .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

      if (env.IsDevelopment())
      {
        // For more details on using the user secret store see https://go.microsoft.com/fwlink/?LinkID=532709
        builder.AddUserSecrets<Startup>();
      }

      builder.AddEnvironmentVariables();
      Configuration = builder.Build();
    }

    public IConfigurationRoot Configuration { get; }
    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
      // Add framework services.
      services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

      services.AddDbContext<LogDbContext>(options =>
        options.UseSqlite(Configuration.GetConnectionString("LogEntriesConnection")));

      // Used by Remember Me
      services.AddDataProtection().PersistKeysToFileSystem(
          new DirectoryInfo(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"/"));

      services.AddIdentity<ApplicationUser, ApplicationRole>()
          .AddEntityFrameworkStores<ApplicationDbContext>()
          .AddDefaultTokenProviders();

      services.Configure<IdentityOptions>(options =>
      {
        // Password settings
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;

        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;

        // Cookie settings
        options.Cookies.ApplicationCookie.SlidingExpiration = true;
        options.Cookies.ApplicationCookie.ExpireTimeSpan = TimeSpan.FromDays(30);
        options.Cookies.TwoFactorRememberMeCookie.ExpireTimeSpan = TimeSpan.FromDays(10);
        options.Cookies.ApplicationCookie.LoginPath = "/Account/Login";
        options.Cookies.ApplicationCookie.LogoutPath = "/Account/Logout";

        // User settings
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = true;

      });

      services.AddMvc()
          .AddJsonOptions(options => options.SerializerSettings.ContractResolver = new DefaultContractResolver());

      services.Configure<Settings>(Configuration.GetSection("Settings"));
      services.AddScoped(cfg => cfg.GetService<IOptionsSnapshot<Settings>>().Value);

      // Add application services.
      services.AddSingleton<IUtilityService, UtilityService>();
      services.AddTransient<IEmailSender, AuthMessageSender>();
      services.AddTransient<ISmsSender, AuthMessageSender>();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(
      IApplicationBuilder app,
      IHostingEnvironment env,
      IOptionsSnapshot<Settings> settings)
    {

      var _settings = settings.Value;

      if (env.IsDevelopment())
      {
        app.UseDeveloperExceptionPage();
        app.UseDatabaseErrorPage();
        app.UseBrowserLink();
      }
      else
      {
        app.UseExceptionHandler("/Home/Error");

      }

      app.UseStatusCodePagesWithReExecute("/Home/Error/{0}");

      app.UseStaticFiles();

      app.UseIdentity();

      // Add external authentication middleware below. To configure them please see https://go.microsoft.com/fwlink/?LinkID=532715

      app.UseMvc(routes =>
      {
        routes.MapRoute(
                  name: "default",
                  template: "{controller=Home}/{action=Index}/{id?}");
      });
    }
  }
}
