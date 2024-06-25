using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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

        public Func<HttpContext, string> GetMicrosoftAuthorizationUrl { get; set; } = DefaultGetMicrosoftAuthorizationUrl;
        public Func<HttpContext, string> GetMicrosoftTokenEndpoint { get; set; } = DefaultGetMicrosoftTokenEndpoint;
        public Func<HttpContext, string, TokenResponse, Task<ClaimsPrincipal>> ValidateUserAsync { get; set; }

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
    }
}