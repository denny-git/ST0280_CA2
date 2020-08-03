using Microsoft.Ajax.Utilities;
using CSC_CA2.Models;
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
    [RoutePrefix("api/Users")]
    public class UsersController : ApiController
    {
        private ApplicationDbContext context = new ApplicationDbContext();

        [Authorize]
        [Route("ViewAll")]
        [HttpGet]
        public async Task<IHttpActionResult> Get()
        {
            List<ApplicationUser> users = await context.Users.ToListAsync();
            List<object> finalResponse = new List<object>();

            foreach(ApplicationUser user in users)
            {
                var record = new
                {
                    id = user.Id,
                    email = user.Email,
                    username = user.UserName,
                    name = user.FirstName + user.LastName,
                    role = user.Roles
                };
                finalResponse.Add(record);
            }
            return Content(HttpStatusCode.OK, finalResponse);
        }
    }
}
