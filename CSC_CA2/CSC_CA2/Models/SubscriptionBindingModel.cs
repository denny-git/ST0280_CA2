using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace CSC_CA2.Models
{
    public class SubscriptionBindingModel
    {
        [Required]
        [Display(Name = "Plan ID")]
        public string PriceId { get; set; }
    }
}