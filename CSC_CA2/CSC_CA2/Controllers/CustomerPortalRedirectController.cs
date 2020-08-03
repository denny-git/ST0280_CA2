using CSC_CA2.Models;
using Microsoft.AspNet.Identity;
using Stripe;
using Stripe.BillingPortal;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace CSC_CA2.Controllers
{        
    [RoutePrefix("api/CustomerPortalRedirect")]

    public class CustomerPortalRedirectController : ApiController
    {
        private ApplicationDbContext context = new ApplicationDbContext();

        [Authorize]
        [Route("CreateSession")]
        [HttpPost]
        public async Task<HttpResponseMessage> CreateSession()
        {
            StripeConfiguration.ApiKey = "sk_test_51GtOtACvBO8inb37b7UXHnJD8T8bzca1dp6U6mxlHqhPM0z2XNlTMMAM5jkmBgU5rpdqQMBpGyTSMGl2RHZek7qV00ctt3Ayxc";
            string userId = User.Identity.GetUserId();
            var user = await context.Users.FirstOrDefaultAsync(x => x.Id.Equals(userId));

            if (user == null)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "The specified user does not exist" });
            }
            

            var options = new SessionCreateOptions
            {
                Customer = user.StripeId,
                ReturnUrl = this.Url.Link("Default", new { Controller = "MyAccount", Action = "ManageAccount" })
            };
            var service = new SessionService();
            try
            {
                Session s = service.Create(options);
                return Request.CreateResponse(HttpStatusCode.OK, new { url = s.Url});
            }
            catch (Exception ex)
            {
                Thread.Sleep(2500);
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = ex.Message });
            }
        }
    }
}
