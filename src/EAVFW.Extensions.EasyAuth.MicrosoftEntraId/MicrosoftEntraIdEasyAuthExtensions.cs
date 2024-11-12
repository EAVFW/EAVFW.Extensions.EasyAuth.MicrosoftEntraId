using EAVFramework;
using EAVFramework.Configuration;
using EAVFramework.Extensions;
using EAVFW.Extensions.SecurityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
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
      

        public static AuthenticatedEAVFrameworkBuilder AddMicrosoftEntraIdEasyAuth<TContext,TIdentity,TSecurityGroup,TSecurityGroupMemeber>(
            this AuthenticatedEAVFrameworkBuilder builder,
            Func<OnCallbackRequest, IEnumerable<Claim>, Task<Guid>> findIdentityAsync,
            Func<HttpContext, string> getMicrosoftAuthorizationUrl , Func<HttpContext, string> getMicrosoftTokenEndpoint)
            where TContext : DynamicContext
            where TIdentity: DynamicEntity,IIdentity
            where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup,new()
            where TSecurityGroupMemeber : DynamicEntity, ISecurityGroupMember, new()
        {
            builder.AddAuthenticationProvider<MicrosoftEntraEasyAuthProvider<TContext,TSecurityGroup,TSecurityGroupMemeber,TIdentity>,
                MicrosoftEntraIdEasyAuthOptions,IConfiguration>((options, config) =>
            { 
                config.GetSection("EAVEasyAuth:MicrosoftEntraId").Bind(options);
                options.FindIdentityAsync = findIdentityAsync;
                options.GetMicrosoftAuthorizationUrl = getMicrosoftAuthorizationUrl;
                options.GetMicrosoftTokenEndpoint = getMicrosoftTokenEndpoint;

            });
            builder.Services.AddScoped<GroupMatcherService<TSecurityGroup>>();

            return builder;
        }

        public static AuthenticatedEAVFrameworkBuilder AddMicrosoftEntraIdEasyAuth<TContext, TIdentity, TSecurityGroup, TSecurityGroupMemeber>(
           this AuthenticatedEAVFrameworkBuilder builder,
           Func<OnCallbackRequest, IEnumerable<Claim>, Task<Guid>> findIdentityAsync)
              where TContext : DynamicContext
            where TIdentity : DynamicEntity, IIdentity
           where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup,new()
           where TSecurityGroupMemeber : DynamicEntity, ISecurityGroupMember,new()
        {
            builder.AddAuthenticationProvider<MicrosoftEntraEasyAuthProvider<TContext,TSecurityGroup, TSecurityGroupMemeber, TIdentity>, MicrosoftEntraIdEasyAuthOptions, IConfiguration>((options, config) =>
            {
                config.GetSection("EAVEasyAuth:MicrosoftEntraId").Bind(options);
                options.FindIdentityAsync = findIdentityAsync; 
            });
            builder.Services.AddScoped<GroupMatcherService<TSecurityGroup>>();

            return builder;
        }
    }
}