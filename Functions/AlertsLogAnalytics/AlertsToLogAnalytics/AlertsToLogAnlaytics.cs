using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AlertsToLogAnalytics
{
    public static class AlertsToLogAnlaytics
    {
        private static async Task<string> GetAccessToken(string tenantId, string clientId, string clientKey)
        {
            string authContextURL = "https://login.windows.net/" + tenantId;
            var authenticationContext = new AuthenticationContext(authContextURL);
            var credential = new ClientCredential(clientId, clientKey);

            var result = await authenticationContext
                .AcquireTokenAsync("https://management.azure.com/", credential);
            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }
            string token = result.AccessToken;
            return token;
        }

        // Build the API signature
        private static string BuildSignature(string message, string secret, ILogger log)
        {
            try
            {
                log.LogInformation("BUILD SIGNATURE - MSG:" + message);
                log.LogInformation("BUILD SIGNATURE - SECRET:" + secret);
                var encoding = new System.Text.ASCIIEncoding();
                byte[] keyByte = Convert.FromBase64String(secret);
                byte[] messageBytes = encoding.GetBytes(message);
                using (var hmacsha256 = new HMACSHA256(keyByte))
                {
                    byte[] hash = hmacsha256.ComputeHash(messageBytes);
                    return Convert.ToBase64String(hash);
                }
            }
            catch (Exception ex)
            {
                log.LogInformation("EXCEPTION BUILD SIGNATURE" + ex.Message);
                return "";
            }
        }

        // Send a request to the POST API endpoint
        private static void PostData(string signature, string date, string json, string customer_id, string timeStampField, string logName, ILogger log)
        {
            try
            {
                string logAnalyticsURL = "https://" + customer_id + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";
                HttpClient httpAlertClient = new HttpClient();
                httpAlertClient.DefaultRequestHeaders.Add("Accept", "application/json");
                httpAlertClient.DefaultRequestHeaders.Add("Log-Type", logName);
                httpAlertClient.DefaultRequestHeaders.Add("Authorization", signature);
                httpAlertClient.DefaultRequestHeaders.Add("x-ms-date", date);
                httpAlertClient.DefaultRequestHeaders.Add("time-generated-field", timeStampField);

                HttpContent httpAlertContent = new StringContent(json, Encoding.UTF8);
                httpAlertContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                Task<HttpResponseMessage> logAlertResponse = httpAlertClient.PostAsync(new Uri(logAnalyticsURL), httpAlertContent);

                HttpContent responseContent = logAlertResponse.Result.Content;
                string result = responseContent.ReadAsStringAsync().Result;
                Console.WriteLine("Return Result: " + result);
                log.LogInformation("RESULT:" + result);
                log.LogInformation("CUSTOMER ID:" + customer_id);
                log.LogInformation("LOG NAME:" + logName);
                log.LogInformation("SIGNATURE:" + signature);
            }
            catch (Exception excep)
            {
                log.LogInformation("POST DATA EXCEPTION:" + excep.Message);
                Console.WriteLine("API Post Exception: " + excep.Message);
            }
        }

        private static void AlertJsonParserAndPostData(string reqJson, string workspaceId, string workspaceKey, ILogger log)
        {
            JObject bodyJObj = JObject.Parse(reqJson);
            string alertSignalType = bodyJObj.SelectToken("data.essentials.signalType").ToString();
            string timeStampField = "";
            var datestring = DateTime.UtcNow.ToString("r");

            StringBuilder jsonStrBuilder = new StringBuilder();
            StringWriter jsonStrWriter = new StringWriter(jsonStrBuilder);
            JsonWriter alertJsonWriter = new JsonTextWriter(jsonStrWriter);
            alertJsonWriter.Formatting = Formatting.Indented;

            string logEventType = "QueryAlertsHistory";

            if (alertSignalType.ToLowerInvariant() == "metric")
            {
                logEventType = "MetricAlertsHistory";
                JToken resltEssentials = bodyJObj.SelectToken("data.essentials");
                List<JToken> allOfLst = bodyJObj.SelectToken("data.alertContext.condition.allOf").ToList();

                alertJsonWriter.WriteStartArray();

                foreach (JToken allOf in allOfLst)
                {
                    List<JToken> allOfDimensions = allOf.SelectToken("dimensions").ToList();

                    alertJsonWriter.WriteStartObject();

                    alertJsonWriter.WritePropertyName("AlertRule");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("alertRule").ToString());

                    alertJsonWriter.WritePropertyName("Severity");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("severity").ToString());

                    alertJsonWriter.WritePropertyName("MonitorCondition");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("monitorCondition").ToString());

                    alertJsonWriter.WritePropertyName("MonitoringService");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("monitoringService").ToString());

                    alertJsonWriter.WritePropertyName("AlertId");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("alertId").ToString());

                    alertJsonWriter.WritePropertyName("OriginalAlertId");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("originAlertId").ToString());

                    alertJsonWriter.WritePropertyName("FiredTime");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("firedDateTime").ToString());

                    alertJsonWriter.WritePropertyName("SignalType");
                    alertJsonWriter.WriteValue(resltEssentials.SelectToken("signalType").ToString());

                    alertJsonWriter.WritePropertyName("MetricName");
                    alertJsonWriter.WriteValue(allOf.SelectToken("metricName").ToString());

                    alertJsonWriter.WritePropertyName("MetricNameSpace");
                    alertJsonWriter.WriteValue(allOf.SelectToken("metricNamespace").ToString());

                    alertJsonWriter.WritePropertyName("Operator");
                    alertJsonWriter.WriteValue(allOf.SelectToken("operator").ToString());

                    alertJsonWriter.WritePropertyName("Threshold");
                    alertJsonWriter.WriteValue(allOf.SelectToken("threshold").ToString());

                    alertJsonWriter.WritePropertyName("TimeAggregation");
                    alertJsonWriter.WriteValue(allOf.SelectToken("timeAggregation").ToString());

                    alertJsonWriter.WritePropertyName("MetricValue");
                    alertJsonWriter.WriteValue(allOf.SelectToken("metricValue").ToString());

                    foreach (JToken allOfDimn in allOfDimensions)
                    {
                        alertJsonWriter.WritePropertyName(allOfDimn.SelectToken("name").ToString());
                        alertJsonWriter.WriteValue(allOfDimn.SelectToken("value").ToString());
                    }

                    alertJsonWriter.WriteEndObject();
                }

                alertJsonWriter.WriteEndArray();
            }
            else if (alertSignalType.ToLowerInvariant() == "log")
            {
                List<JToken> resltColumns = bodyJObj.SelectToken("data.alertContext.SearchResults.tables[0].columns").ToList();
                List<JToken> resltRows = bodyJObj.SelectToken("data.alertContext.SearchResults.tables[0].rows").ToList();

                alertJsonWriter.WriteStartArray();

                foreach (JToken rw in resltRows)
                {
                    alertJsonWriter.WriteStartObject();
                    alertJsonWriter.WritePropertyName("AlertRule");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.essentials.alertRule").ToString());

                    alertJsonWriter.WritePropertyName("Severity");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.essentials.severity").ToString());

                    alertJsonWriter.WritePropertyName("MonitorCondition");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.essentials.monitorCondition").ToString());

                    alertJsonWriter.WritePropertyName("AlertId");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.essentials.alertId").ToString());

                    alertJsonWriter.WritePropertyName("OriginalAlertId");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.essentials.originAlertId").ToString());

                    alertJsonWriter.WritePropertyName("FiredTime");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.essentials.firedDateTime").ToString());

                    alertJsonWriter.WritePropertyName("Query");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.alertContext.SearchQuery").ToString());

                    alertJsonWriter.WritePropertyName("AlertType");
                    alertJsonWriter.WriteValue(bodyJObj.SelectToken("data.alertContext.AlertType").ToString());
                    alertJsonWriter.WritePropertyName(resltColumns[0].SelectToken("name").ToString());
                    alertJsonWriter.WriteValue(rw[0].ToString());
                    alertJsonWriter.WritePropertyName(resltColumns[1].SelectToken("name").ToString());
                    alertJsonWriter.WriteValue(rw[1].ToString());
                    alertJsonWriter.WritePropertyName(resltColumns[2].SelectToken("name").ToString());
                    alertJsonWriter.WriteValue(rw[2].ToString());
                    alertJsonWriter.WriteEndObject();
                }
                alertJsonWriter.WriteEndArray();
            }

            string alertsJsonToLogAnalytics = jsonStrBuilder.ToString();

            //log.LogInformation("FORMATTED JSON : " + alertsJsonToLogAnalytics);



            //// Create a hash for the API signature
            var jsonBytes = Encoding.UTF8.GetBytes(alertsJsonToLogAnalytics);
            string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
            string hashedString = BuildSignature(stringToHash, workspaceKey, log);
            string signature = "SharedKey " + workspaceId + ":" + hashedString;

            PostData(signature, datestring, alertsJsonToLogAnalytics, workspaceId, timeStampField, logEventType, log);
        }

        [FunctionName("AlertsToLogAnlaytics")]
        public static async void Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string workspaceId = Environment.GetEnvironmentVariable("kv-loganalytics-workspace-id", EnvironmentVariableTarget.Process);
            string workspaceKey = Environment.GetEnvironmentVariable("kv-loganalytics-key", EnvironmentVariableTarget.Process);

            log.LogInformation(workspaceId);
            log.LogInformation(workspaceKey);

            // You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            AlertJsonParserAndPostData(JsonConvert.DeserializeObject(requestBody).ToString(), workspaceId, workspaceKey, log);
        }
    }
}
