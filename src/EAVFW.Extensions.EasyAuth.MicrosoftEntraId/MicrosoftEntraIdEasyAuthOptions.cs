using EAVFramework;
using EAVFramework.Endpoints;
using EAVFramework.Extensions;
using EAVFW.Extensions.SecurityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{
    public class MicrosoftEntraIdEasyAuthOptions
       
    {
        /// <summary>
        /// The Entra Client ID (applicationid) used to authenticate with EntraID
        /// </summary>
        public string ClientId { get;  set; }
        /// <summary>
        /// The Entra Client Secret used to authenticate with EntraID
        /// </summary>
        public string ClientSecret { get;  set; }
        /// <summary>
        /// The Entra Tenant ID used to authenticate with EntraID, if not provided the common tenant is used (multitenant signin)
        /// </summary>
        public string TenantId { get;  set; }= "common";
        /// <summary>
        /// If provided the user should be part of this groupid to be given access
        /// </summary>
        public string GroupId { get;  set; }


        public string Scope { get; set; } = "openid email profile";

        public Func<HttpContext, string> GetMicrosoftAuthorizationUrl { get; set; } = DefaultGetMicrosoftAuthorizationUrl;
        public Func<HttpContext, string> GetMicrosoftTokenEndpoint { get; set; } = DefaultGetMicrosoftTokenEndpoint;
        public Func<OnCallbackRequest, IEnumerable<Claim>, Task<Guid>> FindIdentityAsync { get; set; }

      //  public Func<HttpContext, string, TokenResponse, Task<ClaimsPrincipal>> ValidateUserAsync { get; set; }

        private static string DefaultGetMicrosoftAuthorizationUrl(HttpContext context)
        {
            var options = context.RequestServices.GetRequiredService<IOptions<MicrosoftEntraIdEasyAuthOptions>>();
            if (options.Value.TenantId == null) throw new Exception("TenantId is not configured");
            return $"https://login.microsoftonline.com/{options.Value.TenantId}/oauth2/v2.0/authorize";
        }
        private static string DefaultGetMicrosoftTokenEndpoint(HttpContext context)
        {
            var options = context.RequestServices.GetRequiredService<IOptions<MicrosoftEntraIdEasyAuthOptions>>();
            if (options.Value.TenantId == null) throw new Exception("TenantId is not configured");
            return $"https://login.microsoftonline.com/{options.Value.TenantId}/oauth2/v2.0/token";
        }

        public Dictionary<string,string> AccessGroups { get; set; } = new Dictionary<string, string>();

    }
}