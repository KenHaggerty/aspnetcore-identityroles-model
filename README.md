# aspnetcore-identityroles-model
A generic MVC, AspNet Core, EntityFramework Core model referencing the 1.1.2 SDK which includes roles and event log. Supports VS Code by opening the MVC folder then running dotnet restore, dotnet build.

Visual Studio 2017 was released for production on 2017-03-07, but I have been developing with VS 2017 since around the first of the year with the release candidate versions. You can generate a site almost like this model by installing the .NET Core command-line interface (CLI) tools or VS 2017 then using the command below from a command prompt inside an empty folder. This <a href="https://docs.microsoft.com/en-us/dotnet/articles/core/tools/">article</a> explains the commands and installation options.
<p>
  <strong>dotnet new mvc -au Individual -f netcoreapp1.1</strong>
</p>
The templated site will support user registration and logins with a local SQLite database and it also has a minimal logger configured for debugging. The templated site gets you pretty far and should launch from the command line or you can use VS 2017. One new feature uses an appsettings.json file to inject key-value settings on to the context making them available virtually anywhere in your site. This <a href="https://hassantariqblog.wordpress.com/2017/02/20/asp-net-core-step-by-step-guide-to-access-appsettings-json-in-web-project-and-class-library/">article</a> gives a very good explanation of how to configure this feature.

This model is referencing the 1.1.2 SDK. The libraries delivered by <a href="https://www.nuget.org/" target="_blank">NuGet</a> have matured to a very stable platform. Unfortunately, the rapid development of the libraries has left a lot of the existing documentation behind which is why I have published this repository.

The template generates the Identity v2.2 ApplicationUser class and the database tables for roles and claims in Identity v2.2 using EntityFrameworkCore. This model includes the ApplicationRole class, ApplicationUserRole class, AdminController, AdminViewModels and Admin views. I also developed the appsettings.json to include useful site settings, smtp settings and sms settings classes. This model has an injected utility service for an event log stored in a separate SQLite database and stubbed out email and sms message layouts. The first registered user automatically creates Admin, Manager and LogView roles and assigns the Admin role to the user. This model uses roles and settings throughout.

You can clone this repository then add your style and content to make a new and modern MVC, Aspnet Core, EntityFramework Core application or you can use it as a reference when the documentation is confusing. I taught myself these new technologies while looking for contract or full time work but most available employment is on older technology. If you find this model useful and helpful I would appreciate a donation or a job. For examples of sites based on this model visit <a href="https://khaggerty.com/">KHaggerty.Com</a>.

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=M6Z6SJHSUSD4G)
