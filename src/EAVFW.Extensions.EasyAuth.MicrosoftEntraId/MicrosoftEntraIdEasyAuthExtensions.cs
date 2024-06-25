using EAVFramework;
using EAVFramework.Configuration;
using EAVFW.Extensions.SecurityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{
    public class GroupMatcherService<TSecurityGroup>
        where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup
    {

    }
    public static class MicrosoftEntraIdEasyAuthExtensions
    {
      

        public static AuthenticatedEAVFrameworkBuilder AddMicrosoftEntraIdEasyAuth<TSecurityGroup,TSecurityGroupMemeber>(
            this AuthenticatedEAVFrameworkBuilder builder,
            Func<HttpContext, string, TokenResponse, Task<ClaimsPrincipal>> validateUserAsync,
            Func<HttpContext, string> getMicrosoftAuthorizationUrl , Func<HttpContext, string> getMicrosoftTokenEndpoint)
            where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup
            where TSecurityGroupMemeber : DynamicEntity, ISecurityGroupMember
        {
            builder.AddAuthenticationProvider<MicrosoftEntraEasyAuthProvider<TSecurityGroup,TSecurityGroupMemeber>, MicrosoftEntraIdEasyAuthOptions,IConfiguration>((options, config) =>
            { 
                config.GetSection("EAVEasyAuth:MicrosoftEntraId").Bind(options);
                options.ValidateUserAsync = validateUserAsync;
                options.GetMicrosoftAuthorizationUrl = getMicrosoftAuthorizationUrl;
                options.GetMicrosoftTokenEndpoint = getMicrosoftTokenEndpoint;

            });
            builder.Services.AddScoped<GroupMatcherService<TSecurityGroup>>();

            return builder;
        }

        public static AuthenticatedEAVFrameworkBuilder AddMicrosoftEntraIdEasyAuth<TSecurityGroup, TSecurityGroupMemeber>(
           this AuthenticatedEAVFrameworkBuilder builder,
           Func<HttpContext, string, TokenResponse, Task<ClaimsPrincipal>> validateUserAsync)
           where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup
           where TSecurityGroupMemeber : DynamicEntity, ISecurityGroupMember
        {
            builder.AddAuthenticationProvider<MicrosoftEntraEasyAuthProvider<TSecurityGroup, TSecurityGroupMemeber>, MicrosoftEntraIdEasyAuthOptions, IConfiguration>((options, config) =>
            {
                config.GetSection("EAVEasyAuth:MicrosoftEntraId").Bind(options);
                options.ValidateUserAsync = validateUserAsync; 
            });
            builder.Services.AddScoped<GroupMatcherService<TSecurityGroup>>();

            return builder;
        }
    }
}