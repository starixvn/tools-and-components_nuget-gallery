using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using System.Configuration;

namespace NuGetGallery
{
    public partial class AuthenticationController : Controller
    {
        private readonly IFormsAuthenticationService _formsAuthSvc;
        private readonly IUserService _userSvc;
        private const string NexcelEmail = "@nexcel.vn";
        [System.Runtime.InteropServices.DllImport("advapi32.dll")]
        public static extern bool LogonUser(string userName, string domainName, string password, int LogonType, int LogonProvider, ref IntPtr phToken);

        public AuthenticationController(
            IFormsAuthenticationService formsAuthSvc,
            IUserService userSvc)
        {
            _formsAuthSvc = formsAuthSvc;
            _userSvc = userSvc;
        }

        //[RequireRemoteHttps]
        public virtual ActionResult LogOn()
        {
            return View();
        }

        [HttpPost]
        //[RequireRemoteHttps]
        public virtual ActionResult LogOn(SignInRequest request, string returnUrl)
        {
            // TODO: improve the styling of the validation summary
            // TODO: modify the Object.cshtml partial to make the first text box autofocus, or use additional metadata
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Hard code user logon
            string userSetting = ConfigurationManager.AppSettings["Gallery:User"];
            string[] users = userSetting.Split(';');
            int index = Array.IndexOf(users, request.UserNameOrEmail.ToLowerInvariant().Replace(NexcelEmail, string.Empty));

            if (index == -1)
            {
                ModelState.AddModelError(String.Empty, " You do not have permission to login to the Nexcel Nuget Gallery");
                return View();
            }

            var user = _userSvc.FindByUsernameOrEmailAddressAndPassword(
                request.UserNameOrEmail,
                request.Password);

            if (user == null)
            {
                var username = request.UserNameOrEmail.ToLowerInvariant().Replace(NexcelEmail, string.Empty);
                bool isSuccess = IsValidateCredentials(username, request.Password, "spvn");

                if (isSuccess)
                {
                    try
                    {
                        user = _userSvc.Create(username, request.Password, username + NexcelEmail);
                        _userSvc.ConfirmEmailAddress(user, user.EmailConfirmationToken);
                    }
                    catch (EntityException ex)
                    {
                        ModelState.AddModelError(String.Empty, ex.Message);
                        return View();
                    }
                }
                else
                {
                    ModelState.AddModelError(
                        String.Empty,
                        Strings.UserNotFound);

                    return View();
                }
            }

            if (!user.Confirmed)
            {
                ViewBag.ConfirmationRequired = true;
                return View();
            }

            IEnumerable<string> roles = null;
            if (user.Roles.AnySafe())
            {
                roles = user.Roles.Select(r => r.Name);
            }

            _formsAuthSvc.SetAuthCookie(
                user.Username,
                true,
                roles);

            return SafeRedirect(returnUrl);
        }

        public virtual ActionResult LogOff(string returnUrl)
        {
            // TODO: this should really be a POST

            _formsAuthSvc.SignOut();

            return SafeRedirect(returnUrl);
        }

        [NonAction]
        public virtual ActionResult SafeRedirect(string returnUrl)
        {
            if (!String.IsNullOrWhiteSpace(returnUrl)
                && Url.IsLocalUrl(returnUrl)
                && returnUrl.Length > 1
                && returnUrl.StartsWith("/", StringComparison.Ordinal)
                && !returnUrl.StartsWith("//", StringComparison.Ordinal)
                && !returnUrl.StartsWith("/\\", StringComparison.Ordinal))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return Redirect(Url.Home());
            }
        }

        private string GetloggedinUserName()
        {
            System.Security.Principal.WindowsIdentity currentUser = System.Security.Principal.WindowsIdentity.GetCurrent();
            return currentUser.Name;
        }

        private bool IsValidateCredentials(string userName, string password, string domain)
        {
            IntPtr tokenHandler = IntPtr.Zero;
            bool isValid = LogonUser(userName, domain, password, 2, 0, ref tokenHandler);
            return isValid;
        }
    }
}