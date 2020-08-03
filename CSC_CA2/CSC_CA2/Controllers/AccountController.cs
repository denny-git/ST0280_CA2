using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Configuration;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using CSC_CA2.Models;
using CSC_CA2.Providers;
using CSC_CA2.Results;
using System.Web.ModelBinding;
using Newtonsoft.Json;
using System.Web.Hosting;
using System.IO;
using Microsoft.Ajax.Utilities;
using System.Configuration;
using System.Net;
using System.Net.Mail;
using Stripe;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.DynamoDBv2.DataModel;
using Recombee.ApiClient;
using Recombee.ApiClient.ApiRequests;
using Recombee.ApiClient.Bindings;
using System.Threading;
using System.Data.Entity;
using Newtonsoft.Json.Linq;

namespace CSC_CA2.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
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


        private RecombeeClient recombeeClient = new RecombeeClient("thelifetimetalents-prod", "");
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {

                return BadRequest(JsonConvert.SerializeObject(ModelState.Values.Select(e => e.Errors).ToList()));

                //return BadRequest(ModelState);
            }
            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            else
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                string currDateTime = DateTime.Now.AddHours(8).ToString("F");
                var resetLink = this.Url.Link("Default", new { Controller = "MyAccount", Action = "ForgotPassword" });
                string message = "Hi " + user.FirstName + ", <br /><br />The password to your TLTT account was changed at " + currDateTime + " SGT. ";
                message += "If it was you who changed it, you may ignore this email. Else, <a href=\"" + resetLink + "\">reset your password immediately</a>.";
                message += "<br /><br />Regards,<br />The TLTT team";

                bool response = SendEmail("Account password changed", message, true, user.Email);
                return Ok();
            }
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<HttpResponseMessage> Register(RegisterBindingModel model)
        {

            if (!ModelState.IsValid)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, JsonConvert.SerializeObject(ModelState.Values.Select(e => e.Errors).ToList()));
            }

            HttpClient client = new HttpClient();
            var res = client.GetAsync($"https://www.google.com/recaptcha/api/siteverify?secret=&response=" + model.Token).Result;

            if ((int)res.StatusCode != 200)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Something went wrong with reCAPTCHA" });
            }

            string JSONres = res.Content.ReadAsStringAsync().Result;
            dynamic JSONdata = JObject.Parse(JSONres);

            if (JSONdata.success != "true")
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "reCAPTCHA failed", error_code = JSONdata.error_codes });
            }
            else
            {
                if ((double)JSONdata.score < 0.5)
                {
                    return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Unable to register account as Google thinks you're a bot.", score = JSONdata.score });
                }
            }
            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email, FirstName = model.FirstName, LastName = model.LastName };
            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Failed to create user, the email may be taken already" });
            }
            else
            {
                try
                {
                    AmazonDynamoDBClient dynDBclient = new AmazonDynamoDBClient();
                    Table userPlansTable = Table.LoadTable(dynDBclient, "users_plans");
                    var userPlan = new Document();
                    userPlan["UserId"] = user.Id;
                    userPlan["Plan"] = "Free";
                    userPlan["LastPaid"] = null;

                    Document d = userPlansTable.PutItem(userPlan);

                }
                catch (Exception e)
                {
                    await UserManager.DeleteAsync(user); //attempt to rollback changes
                    return Request.CreateResponse(HttpStatusCode.BadRequest, e.Message);
                }

                StripeConfiguration.ApiKey = "";

                var options = new CustomerCreateOptions
                {
                    Metadata = new Dictionary<string, string>() {
                        { "user_id", user.Id }
                    },
                    Email = model.Email

                };

                Customer newCustomer;

                try
                {
                    var service = new CustomerService();
                    newCustomer = service.Create(options);
                }
                catch (Exception e)
                {
                    await UserManager.DeleteAsync(user); //attempt to rollback changes
                    return Request.CreateResponse(HttpStatusCode.BadRequest, e.Message);
                }

                var createdUser = await UserManager.FindByIdAsync(user.Id);
                createdUser.StripeId = newCustomer.Id;
                IdentityResult r = await UserManager.UpdateAsync(createdUser);
                if (!r.Succeeded)
                {
                    var service = new CustomerService();
                    await service.DeleteAsync(newCustomer.Id);
                    await UserManager.DeleteAsync(createdUser);

                    AmazonDynamoDBClient dynDBclient = new AmazonDynamoDBClient();
                    Table userPlansTable = Table.LoadTable(dynDBclient, "users_plans");
                    var userPlan = new Document();
                    userPlan["UserId"] = user.Id;


                    Document d = userPlansTable.DeleteItem(userPlan);

                    return Request.CreateResponse(HttpStatusCode.BadRequest);
                }
                string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                var callbackUrl = this.Url.Link("Default", new { Controller = "MyAccount", Action = "ConfirmEmail", userId = user.Id, code = code });

                //put custom email code here

                await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");
                string message = "Hi " + model.FirstName + ", <br /><br />Thanks for registering with The Lifetime Talents (TLTT). To confirm your email, <a href=\"" + callbackUrl + "\">click here</a>.";
                message += "<br /><br />Regards,<br />The TLTT team";
                bool response;
                try
                {
                    response = SendEmail("Confirm your email address", message, true, model.Email);
                } catch (Exception e)
                {
                    var service = new CustomerService();
                    await service.DeleteAsync(newCustomer.Id);
                    await UserManager.DeleteAsync(createdUser);

                    AmazonDynamoDBClient dynDBclient = new AmazonDynamoDBClient();
                    Table userPlansTable = Table.LoadTable(dynDBclient, "users_plans");
                    var userPlan = new Document();
                    userPlan["UserId"] = user.Id;


                    Document d = userPlansTable.DeleteItem(userPlan);

                    return Request.CreateResponse(HttpStatusCode.BadRequest, e.Message);
                }
                return Request.CreateResponse(HttpStatusCode.OK);
            }
            

        }

        //request password reset email
        [AllowAnonymous]
        [Route("RequestPasswordReset")]
        [HttpPost]
        public async Task<IHttpActionResult> RequestPasswordReset(ForgotPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(JsonConvert.SerializeObject(ModelState.Values.Select(e => e.Errors).ToList()));
            }
            if (await UserManager.FindByEmailAsync(model.Email) != null)
            {
                var user = await UserManager.FindByEmailAsync(model.Email);
                var code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = this.Url.Link("Default", new { Controller = "MyAccount", Action = "ResetPassword", userId = user.Id, code = code });
                string message = "Hi " + user.FirstName + ",<br /><br /> To reset the password of your TLTT account, <a href=\"" + callbackUrl + "\">click here.</a>";
                message += "<br /><br />Regards,<br />The TLTT team";
                bool response = SendEmail("Password reset request", message, true, model.Email);
                return Ok();
            }
            else
            {
                //return Ok anyway since we don't want users to know if the email address is valid or not for security reasons
                return Ok();
            }
        }

        [AllowAnonymous]
        [Route("ResetPassword")]
        [HttpPost]
        public async Task<IHttpActionResult> ResetPassword(ResetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(JsonConvert.SerializeObject(ModelState.Values.Select(e => e.Errors).ToList()));
            }

            IdentityResult result = await UserManager.ResetPasswordAsync(model.UserId, model.ResetToken, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        [Authorize]
        [Route("AccountInfo")]
        [HttpGet]
        public async Task<IHttpActionResult> AccountInfo()
        {
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user == null)
            {
                return NotFound();
            }
            else
            {
                var respObj = new
                {
                    email = user.Email,
                    firstName = user.FirstName,
                    lastName = user.LastName
                };
                return Ok(respObj);
            }
        }

        [Authorize]
        [Route("AccountStatus")]
        [HttpGet]
        public IHttpActionResult AccountStatus()
        {
            try
            {
                var client = new AmazonDynamoDBClient();
                var context = new DynamoDBContext(client);
                string userId = User.Identity.GetUserId();
                UserPlan userPlan = context.Load<UserPlan>(userId);

                string lastPaid;
                string status = "";
                if (userPlan.LastPaid == null)
                {
                    lastPaid = "Not applicable";
                }
                else
                {
                    long lastPaidTimestamp = (long)userPlan.LastPaid;

                    DateTimeOffset lastPaidDate = DateTimeOffset.FromUnixTimeMilliseconds(lastPaidTimestamp);
                    lastPaid = lastPaidDate.DateTime.ToString("G");
                }
                if (userPlan.Status == null)
                {
                    status = "Not applicable";
                }
                else
                {
                    status = userPlan.Status;
                }

                return Ok(new { plan = userPlan.Plan, lastPaid = lastPaid, status = status });
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }

        }

        [Authorize]
        [Route("AccountId")]
        [HttpGet]
        public async Task<IHttpActionResult> GetAccountId()
        {
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user == null)
            {
                return NotFound();
            }
            return Ok(new { id = user.Id });
        }

        [Authorize]
        [Route("UpdateInfo")]
        [HttpPut]
        public async Task<IHttpActionResult> UpdateInfo(UpdateInfoBindingModel model)
        {
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user == null)
            {
                return NotFound();
            }
            else
            {
                user.Email = model.Email;
                user.UserName = model.Email;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                IdentityResult result = await UserManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    return GetErrorResult(result);
                }
            }

        }

        [Authorize]
        [Route("Delete")]
        [HttpDelete]
        public async Task<HttpResponseMessage> Delete()
        {                
            ApplicationDbContext context = new ApplicationDbContext();

            string id = User.Identity.GetUserId();
            var user = await context.Users.Where(x => x.Id.Equals(id)).FirstOrDefaultAsync();

            if (user == null)
            {
                return Request.CreateResponse(HttpStatusCode.NotFound);
            }
            else
            {

                AmazonDynamoDBClient client = new AmazonDynamoDBClient();
                Table userPlansTable = Table.LoadTable(client, "users_plans");
                var userPlan = new Document();

                StripeConfiguration.ApiKey = "";
                if (user.StripeId != null)
                {
                    try
                    {
                        var service = new CustomerService();
                        Customer c = service.Delete(user.StripeId);
                        HttpStatusCode deleteResult = c.StripeResponse.StatusCode;
                        if (deleteResult != HttpStatusCode.OK)
                        {
                            return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "An error occurred while deleting Stripe info." });
                        }
                    }
                    catch (Exception e)
                    {

                        userPlan["UserId"] = user.Id;
                        userPlansTable.DeleteItem(userPlan);


                        user.Email = null;
                        user.StripeId = null;
                        user.UserName = user.Id + "_" + user.UserName;
                        user.IsDeleted = true;

                        await context.SaveChangesAsync();


                        Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
                        return Request.CreateResponse(HttpStatusCode.OK);

                    }


                }

                userPlan["UserId"] = user.Id;
                userPlansTable.DeleteItem(userPlan);

                user.Email = null;
                user.StripeId = null;
                user.UserName = user.Id + "_" + user.UserName;
                user.IsDeleted = true;

                await context.SaveChangesAsync();


                Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);

                return Request.CreateResponse(HttpStatusCode.OK);

            }

        }



        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }
        private bool SendEmail(string subject, string message, bool isBodyHtml, string recepientAddress)
        {
            bool status = false;
            /*try
            {*/
            string HostAddress = ConfigurationManager.AppSettings["Host"].ToString();
            string FormEmailId = ConfigurationManager.AppSettings["MailFrom"].ToString();
            string Password = ConfigurationManager.AppSettings["Password"].ToString();
            string Port = ConfigurationManager.AppSettings["Port"].ToString();
            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress(FormEmailId);
            mailMessage.Subject = subject;
            mailMessage.Body = message;
            mailMessage.IsBodyHtml = isBodyHtml;
            mailMessage.To.Add(new MailAddress(recepientAddress));
            SmtpClient smtp = new SmtpClient();
            smtp.Host = HostAddress;
            smtp.EnableSsl = true;
            NetworkCredential networkCredential = new NetworkCredential();
            networkCredential.UserName = mailMessage.From.Address;
            networkCredential.Password = Password;
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = networkCredential;
            smtp.Port = Convert.ToInt32(Port);
            smtp.Send(mailMessage);
            status = true;
            return status;
            /*}
            catch (Exception e)
            {
                return ;
            }*/
        }


        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(JsonConvert.SerializeObject(ModelState.Values.Select(e => e.Errors).ToList()));
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
