using Microsoft.AspNet.Identity.Owin;
using CSC_CA2.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace CSC_CA2.Controllers
{
    public class MyAccountController : Controller
    {
        private ApplicationUserManager _userManager;

        public MyAccountController()
        {

        }
        public MyAccountController(ApplicationUserManager userManager)
        {
            UserManager = userManager;
        }
        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            if (result.Succeeded)
            {
                return View("ConfirmedEmail");
            }
            else
            {
                return View("Error");
            }
        }

        
        public async Task<ActionResult> ResetPassword(string userId, string code)
        {
            var user = await UserManager.FindByNameAsync(userId);
            if (userId == null || code == null)
            {
                return View("ResetPasswordError");
            }
            else
            {
                return RedirectToAction("SetNewPassword", new { userId = userId, code = code });
            }
        }
        public ActionResult SetNewPassword(string userId, string code)
        {
            return View();
        }
        [Authorize]
        public ActionResult MyTalents()
        {
            return View();
        }
        [Authorize]
        public ActionResult Subscribe()
        {
            return View();
        }
        public ActionResult ForgotPassword()
        {
            return View();
        }   

        public ActionResult ConfirmedEmail()
        {
            return View();
        }
        public ActionResult ConfirmEmailError()
        {
            return View();
        }
        public ActionResult ResetEmailSent()
        {
            return View();
        }
        [Authorize]
        public ActionResult ManageBilling()
        {
            return View();
        }
        [Authorize]
        public ActionResult ChangePassword()
        {
            return View();
        }
        [Authorize]
        public ActionResult EditInfo()
        {
            return View();
        }
        [Authorize]
        public ActionResult ManageAccount()
        {
            return View();
        }
        [Authorize]
        public ActionResult DeleteAccount()
        {
            return View();
        }
    }
}
