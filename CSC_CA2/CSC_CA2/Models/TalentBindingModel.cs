using System;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace CSC_CA2.Models
{
    public class UpdateTalentBindingModel
    {
        [Required]
        [Display(Name = "Name")]
        public string Name { get; set; }

        [Required]
        [Display(Name = "Short name")]
        public string ShortName { get; set; }

        [Required]
        [Display(Name = "Reknown")]
        public string Reknown { get; set; }

        [Required]
        [Display(Name = "Talent profile")]
        public string Profile { get; set; }
    }
}