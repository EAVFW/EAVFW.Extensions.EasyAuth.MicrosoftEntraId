using EAVFramework;
using EAVFramework.Authentication;
using EAVFramework.Endpoints;
using EAVFW.Extensions.SecurityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using static IdentityModel.OidcConstants;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{

    public class MicrosoftEntraEasyAuthProvider<TSecurityGroup, TSecurityGroupMember> : IEasyAuthProvider
        where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup
        where TSecurityGroupMember : DynamicEntity, ISecurityGroupMember, new()
    {
        private readonly IOptions<MicrosoftEntraIdEasyAuthOptions> _options;
        private readonly IHttpClientFactory _clientFactory;

        public string AuthenticationName => "MicrosoftEntraId";

        public HttpMethod CallbackHttpMethod => HttpMethod.Post;

        public bool AutoGenerateRoutes { get; set; } = true;

        public MicrosoftEntraEasyAuthProvider() { }

        public MicrosoftEntraEasyAuthProvider(
            IOptions<MicrosoftEntraIdEasyAuthOptions> options,
            IHttpClientFactory clientFactory)
        {
            _options = options ?? throw new System.ArgumentNullException(nameof(options));
            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        }

        public async Task OnAuthenticate(HttpContext httpcontext, string handleId, string redirectUrl)
        {
            var email = httpcontext.Request.Query["email"].FirstOrDefault();
            var redirectUri = httpcontext.Request.Query["redirectUri"].FirstOrDefault();
            var callbackUri = $"{httpcontext.Request.Scheme}://{httpcontext.Request.Host}{httpcontext.Request.Path}/callback";

            var ru = new RequestUrl(_options.Value.GetMicrosoftAuthorizationUrl(httpcontext));
            var authUri = ru.CreateAuthorizeUrl(
              clientId: _options.Value.ClientId,
              redirectUri: callbackUri,
              responseType: ResponseTypes.Code,
              responseMode: ResponseModes.FormPost,
              scope: _options.Value.Scope,
              loginHint: String.IsNullOrEmpty(email) || email == "undefined" ? null : email,
              state: handleId + "&" + redirectUri);
            httpcontext.Response.Redirect(authUri);
        }

        public async Task<(ClaimsPrincipal, string, string)> OnCallback(HttpContext httpcontext)
        {
            var m = new IdentityModel.Client.AuthorizeResponse(await new StreamReader(httpcontext.Request.Body).ReadToEndAsync());
            var state = m.State.Split(new char[] { '&' }, 2);
            var handleId = state[0];
            var redirectUri = state[1];
            var callbackUri = $"{httpcontext.Request.Scheme}://{httpcontext.Request.Host}{httpcontext.Request.Path}";

            var http = _clientFactory.CreateClient();
            var response = await http.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = _options.Value.GetMicrosoftTokenEndpoint(httpcontext),
                ClientId = _options.Value.ClientId,
                ClientSecret = _options.Value.ClientSecret,
                Code = m.Code,
                RedirectUri = callbackUri,
            });

            ClaimsPrincipal identity = await _options.Value.ValidateUserAsync(httpcontext, handleId, response);
            if (identity == null)
            {
                httpcontext.Response.Redirect($"{httpcontext.Request.Scheme}://{httpcontext.Request.Host}callback?error=access_denied&error_subcode=user_not_found");
                //return;
            }

            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(response.IdentityToken);

            // Get string of group claims from the token
            var groupClaims = jwtSecurityToken.Claims.Where(c => c.Type == "groups");
            if (!groupClaims.Any())
            {
                httpcontext.Response.Redirect($"{httpcontext.Request.Scheme}://{httpcontext.Request.Host}callback?error=access_denied&error_subcode=group_not_found");
                //return;
            }
            // Get the group ids from the claims
            var groupIds = groupClaims.Select(c => new Guid(c.Value)).ToList();
            var db = httpcontext.RequestServices.GetRequiredService<EAVDBContext<DynamicContext>>();

            await SyncUserGroup(identity, groupIds, db);

            return (identity, redirectUri, handleId);
        }

        private async Task SyncUserGroup(ClaimsPrincipal identity, List<Guid> groupIds, EAVDBContext<DynamicContext> db)
        {
            var claimDict = identity.Claims.ToDictionary(c => c.Type, c => c.Value);
            var userId = new Guid(claimDict["sub"]);

            // Fetch all security group members for user
            var groupMembersQuery = db.Set<TSecurityGroupMember>()
                .Where(sgm => sgm.IdentityId == userId);
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
                    sgm.IdentityId = userId;
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