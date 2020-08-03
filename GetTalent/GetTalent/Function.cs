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

namespace GetTalent
{
    public class Function
    {
        public APIGatewayProxyResponse FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
        {
            if(request.PathParameters == null)
            {
                var responseBody = new
                {
                    message = "No talent ID was specified in the request"
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
            string id = request.PathParameters["talentId"];
            string ConnectionString = "Data Source = csc-ca2.c9oqyg5fu7ja.us-east-1.rds.amazonaws.com,1433; Initial Catalog = Users_Talents; user Id = admin; password = CSC_CA2_password";

            object response = new object();
            using (var Conn = new SqlConnection(ConnectionString))
            {
                using (var Cmd = new SqlCommand($"SELECT * from Talents WHERE Id = @id", Conn))
                {
                    // Open SQL Connection
                    Conn.Open();
                    Cmd.Parameters.AddWithValue("@id", id);
                    // Execute SQL Command
                    SqlDataReader rdr = Cmd.ExecuteReader();

                    if (rdr.Read())
                    {
                        response = new
                        {
                            profile = rdr.GetString(1),
                            name = rdr.GetString(2),
                            imageUrl = rdr.GetString(3),
                            shortName = rdr.GetString(5),
                            reknown = rdr.GetString(6),
                        };
                        Conn.Close();
                    }
                    else
                    {
                        Conn.Close();
                        var responseBody = new
                        {
                            message = "No talent with the specified ID exists"
                        };
                        return new APIGatewayProxyResponse
                        {
                            StatusCode = 404,
                            Headers = new Dictionary<string, string>
                                {
                                    { "content-type", "json" },
                                    {"Access-Control-Allow-Origin", "*" }
                                },
                            Body = JsonSerializer.Serialize(responseBody),
                        };
                    }
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
                Body = JsonSerializer.Serialize(response),
            };
        }
    }
}

