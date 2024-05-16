using EAVFramework.Configuration;
using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{
    public static class MicrosoftEntraIdEasyAuthExtensions
    {
        public static AuthenticatedEAVFrameworkBuilder AddMicrosoftEntraIdEasyAuth(this AuthenticatedEAVFrameworkBuilder builder, Func<HttpContext, string, TokenResponse, Task<ClaimsPrincipal>> validateUserAsync)
        {
            builder.AddAuthenticationProvider<MicrosoftEntraEasyAuthProvider, MicrosoftEntraIdEasyAuthOptions,IConfiguration>((options, config) =>
            { 
                config.GetSection("EAVEasyAuth:MicrosoftEntraId").Bind(options);
                options.ValidateUserAsync = validateUserAsync;

            });
            return builder;
        }
    }
}