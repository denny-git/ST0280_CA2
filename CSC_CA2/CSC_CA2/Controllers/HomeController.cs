using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CSC_CA2.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {

            return View();
        }
        public ActionResult Login()
        {
            return View();
        }
        public ActionResult Register()
        {
            return View();
        }
        public ActionResult CreateTalent()
        {
            return View();
        }
        public ActionResult SearchTalents()
        {
            return View();
        }
        public ActionResult Talent()
        {
            return View();
        }
        public ActionResult ViewAllTalents()
        {
            return View();
        }
        [Authorize(Roles = "PaidUser")]
        public ActionResult Discover()
        {
            return View();
        }
        [Authorize]
        public ActionResult EditTalent()
        {
            return View();
        }
    }
}
