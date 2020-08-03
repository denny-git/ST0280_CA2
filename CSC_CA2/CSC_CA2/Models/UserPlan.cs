using Amazon.DynamoDBv2.DataModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CSC_CA2.Models
{
    [DynamoDBTable("users_plans")]
    public class UserPlan
    {
        [DynamoDBHashKey]
        public string UserId { get; set; }
        public string Plan { get; set; }
        public long? LastPaid { get; set; }
        public string Status { get; set; }

    }
}