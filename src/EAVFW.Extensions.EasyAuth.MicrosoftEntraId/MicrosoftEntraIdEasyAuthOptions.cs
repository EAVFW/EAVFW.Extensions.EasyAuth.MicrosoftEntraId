using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{
    public class MicrosoftEntraIdEasyAuthOptions
    {
        public string ClientId { get;  set; }
        public string ClientSecret { get;  set; }
        public string TenantId { get;  set; }
        public string GroupId { get;  set; }
        public string Scope { get;  set; }
        
        public Func<HttpContext, string> GetMicrosoftAuthorizationUrl { get; set; }
        public Func<HttpContext, string> GetMicrosoftTokenEndpoint { get; set; }
        public Func<HttpContext, string, TokenResponse, Task<ClaimsPrincipal>> ValidateUserAsync { get; set; }
    }
}