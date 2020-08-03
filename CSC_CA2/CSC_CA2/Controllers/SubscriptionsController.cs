using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DocumentModel;
using CSC_CA2.Models;
using Microsoft.Ajax.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Stripe;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace CSC_CA2.Controllers
{
    [RoutePrefix("api/Subscriptions")]

    public class SubscriptionsController : ApiController
    {
        ApplicationDbContext context = new ApplicationDbContext();
        private readonly string apiKey = "sk_test_51GtOtACvBO8inb37b7UXHnJD8T8bzca1dp6U6mxlHqhPM0z2XNlTMMAM5jkmBgU5rpdqQMBpGyTSMGl2RHZek7qV00ctt3Ayxc";

        private ApplicationUserManager _userManager;
        public SubscriptionsController()
        {

        }
        public SubscriptionsController(ApplicationUserManager userManager)
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

        [Authorize]
        [Route("Plans")]
        [HttpGet]
        public HttpResponseMessage GetPlans()
        {
            StripeConfiguration.ApiKey = apiKey;
            List<object> storeProductList = new List<object>();

            var productSrv = new ProductService();
            var options = new ProductListOptions { Active = true };
            StripeList<Product> products = productSrv.List(options);
            foreach (Product product in products)
            {
                var priceOptions = new PriceListOptions { Active = true, Product = product.Id };
                var priceSrv = new PriceService();
                StripeList<Price> prices = priceSrv.List(priceOptions);

                Price price = prices.ElementAt(0);

                var item = new
                {
                    price = (long)price.UnitAmount,
                    productId = price.ProductId,
                    priceId = price.Id,
                    name = product.Name,
                    description = product.Description
                };

                storeProductList.Add(item);
            }
            return Request.CreateResponse(HttpStatusCode.OK, storeProductList);
        }

        [Authorize]
        [Route("Subscribe")]
        [HttpPost]
        public async Task<HttpResponseMessage> PostAsync(SubscriptionBindingModel model)
        {

            //create subscription, add user to paiduser role, modify dynamodb
            StripeConfiguration.ApiKey = "sk_test_51GtOtACvBO8inb37b7UXHnJD8T8bzca1dp6U6mxlHqhPM0z2XNlTMMAM5jkmBgU5rpdqQMBpGyTSMGl2RHZek7qV00ctt3Ayxc";

            if (User.IsInRole("PaidUser"))
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "You are already subscribed to a plan. Go to My account > Manage billing to change or cancel your subscription" });
            }

            string userId = User.Identity.GetUserId();

            var user = await context.Users.Where(x => x.Id.Equals(userId)).FirstOrDefaultAsync();

            var options = new SubscriptionCreateOptions
            {
                Customer = user.StripeId,
                Items = new List<SubscriptionItemOptions>
                        {
                            new SubscriptionItemOptions
                            {
                              Price = model.PriceId,
                            },
                        },
            };
            Subscription subscription;
            try
            {
                var service = new SubscriptionService();
                subscription = service.Create(options);
            } catch (StripeException s)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "An error occurred while trying to create your subscription with Stripe. Check that you have a valid payment method defined at My Account > Manage Billing" });
            }
            
            
            var invService = new InvoiceService();
            Invoice inv = invService.Get(subscription.LatestInvoiceId);

            try
            {
                var productSrv = new ProductService();
                Product p = productSrv.Get(subscription.Plan.ProductId);

                AmazonDynamoDBClient client = new AmazonDynamoDBClient();
                Table userPlansTable = Table.LoadTable(client, "users_plans");
                var userPlan = new Document();
                userPlan["UserId"] = user.Id;
                userPlan["Plan"] = p.Name;

                userPlansTable.UpdateItem(userPlan);
            } catch(Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = e.Message });
            }
            await UserManager.AddToRoleAsync(userId, "PaidUser");

            return Request.CreateResponse(HttpStatusCode.OK, new { message = "Successfully created subscription, invoice " + subscription.LatestInvoiceId + " was created.", url = inv.HostedInvoiceUrl });
        }
    }
}
