using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using CSC_CA2.Models;
using Microsoft.Ajax.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Stripe;

namespace CSC_CA2.Controllers
{
    
    public class WebhookController : ApiController
    {
        private ApplicationUserManager _userManager;
        private ApplicationDbContext context = new ApplicationDbContext();
        public WebhookController()
        {

        }

        public WebhookController(ApplicationUserManager userManager)
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

        [HttpPost]
        [Route("api/webhook")]
        public async Task<IHttpActionResult> Index()
        {
            var json = new StreamReader(HttpContext.Current.Request.InputStream).ReadToEnd();

            var stripeEvent = EventUtility.ParseEvent(json);

            if (stripeEvent.Type.Equals(Events.ChargeFailed))
            {
                var charge = stripeEvent.Data.Object as Charge;
                string stripeId = charge.CustomerId;

                var user = context.Users.Where(x => x.StripeId.Equals(stripeId)).FirstOrDefault();
                if(user == null)
                {
                    return Ok();
                }
                AmazonDynamoDBClient client = new AmazonDynamoDBClient();
                var dynamoDBContext = new DynamoDBContext(client);

                UserPlan userPlan = dynamoDBContext.Load<UserPlan>(user.Id);

                Table userPlansTable = Table.LoadTable(client, "users_plans");

                var userPlanUpdated = new Document();
                userPlanUpdated["UserId"] = user.Id;
                userPlanUpdated["Status"] = "Payment method needs attention";

                userPlansTable.UpdateItem(userPlanUpdated);
                return Ok();
            }
            else if (stripeEvent.Type.Equals(Events.ChargeSucceeded))
            {
                var charge = stripeEvent.Data.Object as Charge;
                string stripeId = charge.CustomerId;

                var user = context.Users.Where(x => x.StripeId.Equals(stripeId)).FirstOrDefault();
                if (user == null)
                {
                    return BadRequest("User does not exist");
                }
                AmazonDynamoDBClient client = new AmazonDynamoDBClient();
                var dynamoDBContext = new DynamoDBContext(client);

                UserPlan userPlan = dynamoDBContext.Load<UserPlan>(user.Id);

                Table userPlansTable = Table.LoadTable(client, "users_plans");

                var userPlanUpdated = new Document();
                userPlanUpdated["UserId"] = user.Id;
                userPlanUpdated["LastPaid"] = DateTimeOffset.UtcNow.AddHours(8).ToUnixTimeMilliseconds();
                userPlanUpdated["Status"] = "Active";

                userPlansTable.UpdateItem(userPlanUpdated);
                return Ok();
            }
            else if (stripeEvent.Type.Equals(Events.CustomerSubscriptionDeleted))
            {
                var subscription = stripeEvent.Data.Object as Subscription;
                string stripeId = subscription.CustomerId;

                var user = context.Users.Where(x => x.StripeId.Equals(stripeId)).FirstOrDefault();
                if(user == null)
                {
                    return Ok();
                }
                string userId = user.Id;

                AmazonDynamoDBClient client = new AmazonDynamoDBClient();
                Table userPlansTable = Table.LoadTable(client, "users_plans");
                var userPlan = new Document();
                userPlan["UserId"] = user.Id;
                userPlan["Plan"] = "Free";
                userPlan["LastPaid"] = null;
                userPlan["Status"] = null;

                userPlansTable.UpdateItem(userPlan);

                await UserManager.RemoveFromRoleAsync(userId, "PaidUser");
                return Ok();
            }    
            return Ok();
        }
    }
}
