using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace CSC_CA2.Models
{
    public class Talent
    {
        [Key]
        public string Id { get; set; }
        public string Profile { get; set; }
        public string Name { get; set; }
        public string ShortName { get; set; }
        public string Reknown { get; set; }
        public string Url { get; set; }
        public virtual ApplicationUser user { get; set; }
    }
}