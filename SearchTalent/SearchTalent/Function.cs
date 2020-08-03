using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace SearchTalent
{
    public class Function
    {
        public APIGatewayProxyResponse FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
        {
            if (request.PathParameters == null)
            {
                var responseBody = new
                {
                    message = "No search term was specified in the request"
                };
                return new APIGatewayProxyResponse
                {
                    StatusCode = 400,
                    Headers = new Dictionary<string, string>
                {
                    { "content-type", "json" },
                    {"Access-Control-Allow-Origin", "*" }
                },
                    Body = JsonSerializer.Serialize(responseBody),
                };
            }
            string searchTerm = request.PathParameters["searchTerm"];
            string ConnectionString = "Data Source = csc-ca2.c9oqyg5fu7ja.us-east-1.rds.amazonaws.com,1433; Initial Catalog = Users_Talents; user Id = admin; password = ";

            int count = 0;
            List<object> items = new List<object>();
            using (var Conn = new SqlConnection(ConnectionString))
            {
                using (var Cmd = new SqlCommand($"SELECT * from Talents WHERE ShortName LIKE @name", Conn))
                {
                    // Open SQL Connection
                    Conn.Open();
                    Cmd.Parameters.AddWithValue("@name", "%" + searchTerm + "%");
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
                    {"Access-Control-Allow-Origin", "*" }
                },
                Body = JsonSerializer.Serialize(items),
            };
        }
    }
}

