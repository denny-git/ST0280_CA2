using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin;
using CSC_CA2.Models;
using System.Web;
using Microsoft.Ajax.Utilities;
using System.Web.Hosting;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon;
using Clarifai.API;
using Clarifai.DTOs.Inputs;
using Clarifai.DTOs.Predictions;
using Amazon.DynamoDBv2.Model;
using Newtonsoft.Json;
using Recombee.ApiClient;
using Recombee.ApiClient.ApiRequests;
using Org.BouncyCastle.Asn1.Cms;

namespace CSC_CA2.Controllers
{
    [RoutePrefix("api/Talents")]
    public class TalentsController : ApiController
    {
        private ApplicationDbContext context = new ApplicationDbContext();
        private ApplicationUserManager _userManager;

        public TalentsController()
        {

        }

        public TalentsController(ApplicationUserManager userManager)
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
        private RecombeeClient recombeeClient = new RecombeeClient("thelifetimetalents-prod", "3CpbpUe4JvX3VOcrZqqaLEQ6jYCcIul8EQphej4VH4Qo0nw48MONgsnwpDcymxs3");

        private static readonly RegionEndpoint bucketRegion = RegionEndpoint.USEast1;
        private static readonly string bucketName = "csc-2020-ca2";
        static readonly IAmazonS3 s3Client = new AmazonS3Client(bucketRegion);
        private static async Task<PutObjectResponse> UploadFileAsync(Stream stream, string keyName)
        {
            var putRequest = new PutObjectRequest
            {
                BucketName = bucketName,
                Key = keyName,
                InputStream = stream,
                CannedACL = S3CannedACL.PublicRead
            };
            PutObjectResponse response = await s3Client.PutObjectAsync(putRequest);
            return response;
        }
        private static async Task<DeleteObjectResponse> DeleteFileAsync(string keyName)
        {
            var deleteRequest = new DeleteObjectRequest
            {
                Key = keyName,
                BucketName = bucketName
            };
            DeleteObjectResponse response = await s3Client.DeleteObjectAsync(deleteRequest);
            return response;
        }

        [Authorize]
        [Route("Create")]
        [System.Web.Mvc.HttpPost]
        public async Task<HttpResponseMessage> SaveFile()
        {
            var filesReadToProvider = await Request.Content.ReadAsMultipartAsync();
            byte[] fileBytes;

            string userId = User.Identity.GetUserId();

            var user = await context.Users.FirstOrDefaultAsync(x => x.Id.Equals(userId));

            if (user == null)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "User is null" });
            }

            if (filesReadToProvider.Contents == null)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "No file received" });
            }
            else
            {
                if (filesReadToProvider.Contents[0] == null || filesReadToProvider.Contents[1] == null)
                {
                    return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Received a bad request with missing parameters" });
                }
                else
                {
                    fileBytes = await filesReadToProvider.Contents[0].ReadAsByteArrayAsync();
                    var name = await filesReadToProvider.Contents[1].ReadAsStringAsync();
                    var shortName = await filesReadToProvider.Contents[2].ReadAsStringAsync();
                    var reknown = await filesReadToProvider.Contents[3].ReadAsStringAsync();
                    var profile = await filesReadToProvider.Contents[4].ReadAsStringAsync();
                    if(name.Equals("") || shortName.Equals("") || reknown.Equals("") || profile.Equals(""))
                    {
                        return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Please ensure that you have filled in all the fields." });
                    }
                    if (fileBytes.Length <= 64)
                    {
                        return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Received bad image file" });
                    }
                    else
                    {
                        try
                        {
                            var client = new ClarifaiClient("35eb832889864fb0825e9b1be6a2d11e");
                            var clarifaiTagsResult = await client.PublicModels.NsfwModel.Predict(new ClarifaiFileImage(fileBytes)).ExecuteAsync();

                            List<Concept> probabilities = clarifaiTagsResult.Get().Data;
                            var sfwProbability = probabilities[0].Value;
                            var nsfwProbability = probabilities[1].Value;
                            if( sfwProbability < 0.15M || nsfwProbability > 0.85M)
                            {
                                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Image is most likely NSFW and not suitable for upload", sfwProbability = sfwProbability, nsfwProbability = nsfwProbability });
                            } else
                            {
                                string guid = string.Format(@"{0}", Guid.NewGuid());

                                Stream stream = new MemoryStream(fileBytes);

                                PutObjectResponse r = await UploadFileAsync(stream, guid);

                                if(r.HttpStatusCode == HttpStatusCode.OK)
                                {
                                    //add logic to create DynamoDB entry

                                    Talent t = new Talent();

                                    t.Id = guid;
                                    t.Name = name;
                                    t.ShortName = shortName;
                                    t.Reknown = reknown;
                                    t.Profile = profile;
                                    t.Url = "https://" + bucketName + ".s3.amazonaws.com/" + guid ;
                                    t.user = user;

                                    context.Talents.Add(t);
                                    context.SaveChanges();

                                    Dictionary<string, object> properties = new Dictionary<string, object>
                                    {
                                        { "name", shortName }
                                    };
                                    SetItemValues createItemRequest = new SetItemValues(guid, properties, cascadeCreate: true);
                                    createItemRequest.Timeout = TimeSpan.FromSeconds(3);
                                    await recombeeClient.SendAsync(createItemRequest);

                                    return Request.CreateResponse(HttpStatusCode.OK, new { message = "Success", sfwProbability = sfwProbability, nsfwProbability = nsfwProbability, talentId = guid });
                                } else
                                {
                                    return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Failed to upload to S3" });
                                }
                            }
     
                        } catch(Exception e)
                        {
                            return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = e.Message });
                        }
                    }
                }
            }
        }

        [Authorize]
        [Route("ViewMyTalents")]
        [HttpGet]
        public async Task<IHttpActionResult> ViewMyTalents()
        {
            string userId = User.Identity.GetUserId();
            var user = await context.Users.FirstOrDefaultAsync(x => x.Id.Equals(userId));



            List<Talent> recordings = context.Talents.Where(x => x.user.Id == userId).ToList();
            int count = await context.Talents.CountAsync(x => x.user.Id.Equals(userId));

            List<object> recordsResponse = new List<object>();
            foreach (Talent r in recordings)
            {
                var recording = new
                {
                    id = r.Id,
                    name = r.ShortName,
                    imageUrl = r.Url
                };
                recordsResponse.Add(recording);
            }
            
            return Content(HttpStatusCode.OK, recordsResponse);
        }

        [Route("ViewAll")]
        [HttpGet]
        public async Task<IHttpActionResult> ViewAllTalents()
        {
            var talentsList = await context.Talents.ToListAsync();
            List<object> response = new List<object>();
            foreach(Talent t in talentsList)
            {
                var item = new
                {
                    id = t.Id,
                    imageUrl = t.Url,
                    name = t.ShortName,
                };
                response.Add(item);
            }
            return Content(HttpStatusCode.OK, response);
        }

        [Route("ViewSingleTalent/{id}")]
        [HttpGet]
        public async Task<IHttpActionResult> GetSingleTranscription(string id)
        {
            var talentToView = await context.Talents.FirstOrDefaultAsync(x => x.Id.Equals(id));

            if (talentToView != null)
            {
                var finalResponse = new
                {
                    name = talentToView.Name,
                    shortName = talentToView.ShortName,
                    reknown = talentToView.Reknown,
                    profile = talentToView.Profile,
                    imageUrl = talentToView.Url
                };
                return Content(HttpStatusCode.OK, finalResponse);
            }
            else
            {
                return Content(HttpStatusCode.BadRequest, new { message = "The talent ID specified is invalid" });
            }
        }

        [Route("Search")]
        [HttpGet]
        public async Task<IHttpActionResult> SearchTalent(string searchTerm)
        {
            var talentsList = await context.Talents.Where(x => x.ShortName.Contains(searchTerm)).ToListAsync();
            List<object> response = new List<object>();
            foreach (Talent t in talentsList)
            {
                var item = new
                {
                    id = t.Id,
                    imageUrl = t.Url,
                    name = t.ShortName,
                };
                response.Add(item);
            }
            
            return Content(HttpStatusCode.OK, response);
        }

        [Authorize]
        [Route("Delete/{id}")]
        [HttpDelete]
        public async Task<HttpResponseMessage> Delete(string id)
        {
            string userId = User.Identity.GetUserId();
            var talentToDelete = await context.Talents.FirstOrDefaultAsync(x => x.Id.Equals(id) && x.user.Id.Equals(userId));
            if (talentToDelete == null)
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "The record selected for deletion was not found. It may have been deleted already." });
            }
            if (talentToDelete != null)
            {
                context.Talents.Remove(talentToDelete);
                DeleteObjectResponse r = await DeleteFileAsync(talentToDelete.Id);
                if (r.HttpStatusCode == HttpStatusCode.NoContent)
                {
                    context.SaveChanges();

                    DeleteItem deleteItemRequest = new DeleteItem(id);
                    deleteItemRequest.Timeout = TimeSpan.FromSeconds(3);
                    await recombeeClient.SendAsync(deleteItemRequest);

                    return Request.CreateResponse(HttpStatusCode.OK, new { message = "Successfully deleted record" });
                }
                else
                {
                    return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Failed to delete from S3", code = r.HttpStatusCode.ToString() });
                }
            }
            else
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "The record selected for deletion was not found" });
            }
        }

        [Authorize]
        [Route("Edit/{id}")]
        [HttpPut]
        public async Task<IHttpActionResult> Edit(string id, UpdateTalentBindingModel model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(JsonConvert.SerializeObject(ModelState.Values.Select(e => e.Errors).ToList()));
            }
            string userId = User.Identity.GetUserId();
            var talentToEdit = await context.Talents.FirstOrDefaultAsync(x => x.Id.Equals(id) && x.user.Id.Equals(userId));

            if (talentToEdit == null)
            {
                return NotFound();
            }
            else
            {
                talentToEdit.Name = model.Name;
                talentToEdit.ShortName = model.ShortName;
                talentToEdit.Reknown = model.Reknown;
                talentToEdit.Profile = model.Profile;
                context.SaveChanges();

                Dictionary<string, object> properties = new Dictionary<string, object>
                                    {
                                        { "name", model.ShortName }
                                    };
                SetItemValues createItemRequest = new SetItemValues(talentToEdit.Id, properties, cascadeCreate: true);
                createItemRequest.Timeout = TimeSpan.FromSeconds(3);
                await recombeeClient.SendAsync(createItemRequest);

                return Ok(new { message = "Changes saved successfully." });
            }
        }
    }
}