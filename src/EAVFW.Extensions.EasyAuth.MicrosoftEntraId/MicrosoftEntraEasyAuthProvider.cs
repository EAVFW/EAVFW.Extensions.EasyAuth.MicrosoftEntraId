using EAVFramework;
using EAVFramework.Authentication;
using EAVFramework.Authentication.Passwordless;
using EAVFramework.Configuration;
using EAVFramework.Endpoints;
using EAVFramework.Extensions;
using EAVFW.Extensions.SecurityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using static IdentityModel.OidcConstants;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{

    public class MicrosoftEntraEasyAuthProvider<TContext,TSecurityGroup, TSecurityGroupMember,TIdentity> : DefaultAuthProvider
        where TContext : DynamicContext
        where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup
        where TSecurityGroupMember : DynamicEntity, ISecurityGroupMember, new()
        where TIdentity : DynamicEntity, IIdentity
    {
        private readonly IOptions<MicrosoftEntraIdEasyAuthOptions> _options;
        private readonly IHttpClientFactory _clientFactory;
          

        public MicrosoftEntraEasyAuthProvider() :base("MicrosoftEntraId", HttpMethod.Post) { }

        public MicrosoftEntraEasyAuthProvider(
            IOptions<MicrosoftEntraIdEasyAuthOptions> options,
            IHttpClientFactory clientFactory) : this()
        {
            _options = options ?? throw new System.ArgumentNullException(nameof(options));
            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        }

        public override async Task<OnAuthenticateResult> OnAuthenticate(OnAuthenticateRequest authenticateRequest)
        {
            

            var callbackurl = new Uri(authenticateRequest.CallbackUrl);
           
            var ru = new RequestUrl(_options.Value.GetMicrosoftAuthorizationUrl(authenticateRequest.HttpContext));
            var authUri = ru.CreateAuthorizeUrl(
              clientId: _options.Value.ClientId,
              redirectUri: callbackurl.GetLeftPart(UriPartial.Path),
              responseType: ResponseTypes.Code,
              responseMode: ResponseModes.FormPost,
              scope: _options.Value.Scope,
              loginHint: authenticateRequest.IdentityId.HasValue ?
               await authenticateRequest.Options.FindEmailFromIdentity(
                   new EmailDiscoveryRequest
                   {
                       HttpContext = authenticateRequest.HttpContext,
                       IdentityId = authenticateRequest.IdentityId.Value,
                       ServiceProvider = authenticateRequest.ServiceProvider
                   }):null,
        state: callbackurl.GetLeftPart(UriPartial.Path));
         
            authenticateRequest.HttpContext.Response.Redirect(authUri);

            return new OnAuthenticateResult { Success = true };
        }

        private async Task<ClaimsPrincipal> ValidateMicrosoftEntraIdUser(OnCallbackRequest request, Guid handleid, JsonWebToken jwtSecurityToken)
        {

            
           


            var user = await _options.Value.FindIdentityAsync(request, jwtSecurityToken.Claims);
            


           var identity = new ClaimsIdentity(new[]
            {
               
                new Claim(IdentityModel.JwtClaimTypes.Subject, user.ToString()),
            }, "MicrosoftEntraId");

            return new ClaimsPrincipal(identity);


        }

        public override async Task PopulateCallbackRequest(OnCallbackRequest request)
        {
            var m = new IdentityModel.Client.AuthorizeResponse(await new StreamReader(request.HttpContext.Request.Body).ReadToEndAsync());

            var query = QueryHelpers.ParseNullableQuery(m.State);

            if (query.TryGetValue("token", out var handleid))
            {
                request.HandleId = new Guid(handleid);
            }
            request.Props.Add("code", m.Code);
            request.Props.Add("state", m.State);

             
        }
        public override async Task<OnCallBackResult> OnCallback(OnCallbackRequest callbackRequest)
        {
            var httpcontext= callbackRequest.HttpContext; 
             
             
            
            var http = _clientFactory.CreateClient();
            var response = await http.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = _options.Value.GetMicrosoftTokenEndpoint(httpcontext),
                ClientId = _options.Value.ClientId,
                ClientSecret = _options.Value.ClientSecret,
                Code = callbackRequest.Props["code"],
                RedirectUri = callbackRequest.Props["state"],
            });

            var handler = new JsonWebTokenHandler();

            var jwtSecurityToken = handler.ReadJsonWebToken(response.IdentityToken);


            ClaimsPrincipal identity = await ValidateMicrosoftEntraIdUser(callbackRequest, callbackRequest.HandleId, jwtSecurityToken);
           
            if (identity == null)
            {
                return new OnCallBackResult { ErrorCode = "access_denied", ErrorSubCode = "user_validation_failed", ErrorMessage = "User could not be validated", Success = false };
             
            }

            
            var groupClaims = jwtSecurityToken.Claims.Where(c => c.Type == "groups");

            if (!string.IsNullOrEmpty(_options.Value.GroupId))
            {

                if (!groupClaims.Any(x=>x.Value == _options.Value.GroupId))
                {
                     return new OnCallBackResult { ErrorCode = "access_denied", ErrorSubCode = "user_access_group_missing", ErrorMessage = "User does not have access", Success = false };

                }
            }
             
            var groupIds = groupClaims.Select(c => new Guid(c.Value)).ToList();
            var db = httpcontext.RequestServices.GetRequiredService<EAVDBContext<DynamicContext>>();

            await SyncUserGroup(identity, groupIds, db);

            return new OnCallBackResult { Principal = identity, Success = true };
        }

        private async Task SyncUserGroup(ClaimsPrincipal identity, List<Guid> groupIds, EAVDBContext<DynamicContext> db)
        {
            var identityId = Guid.Parse(identity.FindFirstValue("sub"));

            // Fetch all security group members for user
            var groupMembersQuery = db.Set<TSecurityGroupMember>()
                .Where(sgm => sgm.IdentityId == identityId);
            // Fetch in memory
            var groupMembersDict = await groupMembersQuery.ToDictionaryAsync(sgm => sgm.Id);

            // Fetch all security groups
            var groupsDict = await db.Set<TSecurityGroup>()
                .Where(sg => groupMembersQuery.Any(sgm => sgm.SecurityGroupId == sg.Id) ||
                                         (sg.EntraIdGroupId != null && groupIds.Contains(sg.EntraIdGroupId.Value)))
                .ToDictionaryAsync(sg => sg.Id);


            // Fetch specific security group and group members
            var sgGroupSpecific = groupsDict.Values.Where(sg => sg.EntraIdGroupId != null && groupIds.Contains(sg.EntraIdGroupId.Value)).ToDictionary(sg => sg.Id);
            var sgmGroupSpecific = groupMembersDict.Values.Where(sgm => sgm.SecurityGroupId != null && sgGroupSpecific.ContainsKey((Guid) sgm.SecurityGroupId));

            // Check if member group exists else add it
            bool isDirty = false;
            foreach (var sg in sgGroupSpecific.Values)
            {
                if (!sgmGroupSpecific.Any(sgm => sgm.SecurityGroupId == sg.Id))
                {
                    var sgm = new TSecurityGroupMember();
                    sgm.IdentityId = identityId;
                    sgm.SecurityGroupId = sg.Id;
                    db.Add(sgm);

                    isDirty = true;
                }
            }

            // Fecth expired group members by comparing the "historical" group members with that of the current based on the group ids
            var expiredGroupMembers = groupMembersDict.Values.Where(sgm =>
                                                !sgmGroupSpecific.Any(x => x.Id == sgm.Id) &&   
                                                sgm.SecurityGroupId != null &&
                                                groupsDict[(Guid) sgm.SecurityGroupId].EntraIdGroupId != null); // Groups of higher aurthority has no EntraGroupId and should not be removed
            foreach (var sgm in expiredGroupMembers)
            {
                db.Remove(sgm);
                isDirty = true;
            }

            if (isDirty) await db.SaveChangesAsync(identity);
        }

        public RequestDelegate OnSignedOut()
        {
            throw new System.NotImplementedException();
        }

        public RequestDelegate OnSignout(string callbackUrl)
        {
            throw new System.NotImplementedException();
        }

        public RequestDelegate OnSingleSignOut(string callbackUrl)
        {
            throw new System.NotImplementedException();
        }
    }
}