using System;
using System.Linq;
using System.Threading.Tasks;
using System.Data.SqlClient;
using Amazon.Lambda.Core;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using Amazon.Lambda.APIGatewayEvents;
// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace GetAllTalents
{
    public class Function
    {
        public APIGatewayProxyResponse FunctionHandler(object input, ILambdaContext context)
        {
            string ConnectionString = "Data Source = csc-ca2.c9oqyg5fu7ja.us-east-1.rds.amazonaws.com,1433; Initial Catalog = Users_Talents; user Id = admin; password = CSC_CA2_password";
            int count = 0;
            List<object> items = new List<object>();
            using (var Conn = new SqlConnection(ConnectionString))
            {
                using (var Cmd = new SqlCommand($"SELECT * from Talents", Conn))
                {
                    // Open SQL Connection
                    Conn.Open();

                    // Execute SQL Command
                    SqlDataReader rdr = Cmd.ExecuteReader();

                    // Loop through the results and add to list
                    while (rdr.Read())
                    {
                        count++;
                        var item = new
                        {
                            id = rdr.GetString(0),
                            imageUrl = rdr.GetString(3),
                            name = rdr.GetString(5),
                        };
                        items.Add(item);
                    }
                    Conn.Close();
                }
            }

            return new APIGatewayProxyResponse
            {
                StatusCode = 200,
                Headers = new Dictionary<string, string>
                {
                    { "content-type", "json" },
                    {"Access-Control-Allow-Origin", "tltt.ddns.net" }
                },
                Body = JsonSerializer.Serialize(items),
            };
        }
    }
}
