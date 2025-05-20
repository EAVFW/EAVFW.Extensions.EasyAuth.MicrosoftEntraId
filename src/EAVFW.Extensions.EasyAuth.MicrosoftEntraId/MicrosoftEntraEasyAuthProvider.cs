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
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Threading.Tasks;
using static IdentityModel.OidcConstants;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{

    public class MicrosoftEntraEasyAuthProvider<TContext,TSecurityGroup, TSecurityGroupMember,TIdentity> : DefaultAuthProvider
        where TContext : DynamicContext
        where TSecurityGroup : DynamicEntity, IEntraIDSecurityGroup,new()
        where TSecurityGroupMember : DynamicEntity, ISecurityGroupMember, new()
        where TIdentity : DynamicEntity, IIdentity
    {
        private readonly IOptions<MicrosoftEntraIdEasyAuthOptions> _options;
        private readonly IOptions<EAVFrameworkOptions> _frameworkOptions;
        private readonly ILogger _logger;
        private readonly IHttpClientFactory _clientFactory;
          

        public MicrosoftEntraEasyAuthProvider() :base("MicrosoftEntraId", HttpMethod.Post) { }

        public MicrosoftEntraEasyAuthProvider(
            IOptions<MicrosoftEntraIdEasyAuthOptions> options,
            IOptions<EAVFrameworkOptions> frameworkOptions,
            ILoggerFactory loggerFactory,
            IHttpClientFactory clientFactory) : this()
        {
            _options = options ?? throw new System.ArgumentNullException(nameof(options));
            _frameworkOptions = frameworkOptions;
            _logger = loggerFactory.CreateLogger("MicrosoftEntraEasyAuthProvider");
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
            _logger.LogDebug("OnCallback called with {0}", callbackRequest.HandleId);
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

            // Log JWT token structure
            _logger.LogDebug("JWT token parsed. Claims count: {0}", jwtSecurityToken.Claims.Count());
            foreach (var claim in jwtSecurityToken.Claims)
            {
                _logger.LogTrace("JWT token claim: {0} = {1}", claim.Type, claim.Value);
            }

            ClaimsPrincipal identity = await ValidateMicrosoftEntraIdUser(callbackRequest, callbackRequest.HandleId, jwtSecurityToken);
           
            if (identity == null)
            {
                return new OnCallBackResult { ErrorCode = "access_denied", ErrorSubCode = "user_validation_failed", ErrorMessage = "User could not be validated", Success = false };
             
            }

            if (_options.Value.LogTokenResponse)
            {
                _logger.LogInformation("User {0} authenticated: {1}", identity.FindFirstValue("sub"), response.Raw);
            }

            var groupClaims = jwtSecurityToken.Claims.Where(c => c.Type == "groups").ToList();
            _logger.LogInformation("Found {0} group claims for user {1}", groupClaims.Count, identity.FindFirstValue("sub"));
            
            foreach (var groupClaim in groupClaims)
            {
                _logger.LogDebug("User has group: {0}", groupClaim.Value);
            }

            if (!string.IsNullOrEmpty(_options.Value.GroupId))
            {
                _logger.LogDebug("Checking if user is in required group {0}", _options.Value.GroupId);
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
            _logger.LogDebug("Starting SyncUserGroup for user {0} with {1} groups", identityId, groupIds.Count);
            
            // Log the groups the user is in
            foreach (var groupId in groupIds)
            {
                _logger.LogDebug("User has Entra ID group: {0}", groupId);
            }

            // Fetch all security group members for user
            var groupMembersQuery = db.Set<TSecurityGroupMember>()
                .Where(sgm => sgm.IdentityId == identityId);
            // Fetch in memory
            var groupMembersDict = await groupMembersQuery.ToDictionaryAsync(sgm => sgm.Id);
            _logger.LogDebug("Found {0} existing security group memberships for user", groupMembersDict.Count);

            await EnsureAccessGroupsCreated(db);

            // Fetch all security groups
            var groupsQuery = db.Set<TSecurityGroup>()
                .Where(sg => groupMembersQuery.Any(sgm => sgm.SecurityGroupId == sg.Id) ||
                             (sg.EntraIdGroupId != null && groupIds.Contains(sg.EntraIdGroupId.Value)));
            
            _logger.LogDebug("Querying security groups with SQL: {0}", groupsQuery.ToQueryString());
            
            var groupsDict = await groupsQuery.ToDictionaryAsync(sg => sg.Id);
            _logger.LogDebug("Found {0} relevant security groups", groupsDict.Count);

            // Log the groups fetched
            foreach (var group in groupsDict.Values)
            {
                _logger.LogDebug("Security group: {0}, Name: {1}, EntraIdGroupId: {2}", 
                    group.Id, group.Name, group.EntraIdGroupId);
            }

            // Fetch specific security group and group members
            var sgGroupSpecific = groupsDict.Values
                .Where(sg => sg.EntraIdGroupId != null && groupIds.Contains(sg.EntraIdGroupId.Value))
                .ToDictionary(sg => sg.Id);
            
            _logger.LogDebug("Found {0} matching security groups with EntraId", sgGroupSpecific.Count);

            var sgmGroupSpecific = groupMembersDict.Values
                .Where(sgm => sgm.SecurityGroupId != null && sgGroupSpecific.ContainsKey((Guid)sgm.SecurityGroupId))
                .ToList();
            
            _logger.LogDebug("User is already a member of {0} matching security groups", sgmGroupSpecific.Count);

            // Check if member group exists else add it
            bool isDirty = false;
            foreach (var sg in sgGroupSpecific.Values)
            {
                if (!sgmGroupSpecific.Any(sgm => sgm.SecurityGroupId == sg.Id))
                {
                    _logger.LogDebug("Adding user to security group: {0}, Name: {1}, EntraIdGroupId: {2}", 
                        sg.Id, sg.Name, sg.EntraIdGroupId);
                    
                    var sgm = new TSecurityGroupMember();
                    sgm.IdentityId = identityId;
                    sgm.SecurityGroupId = sg.Id;
                    db.Add(sgm);

                    isDirty = true;
                }
            }

            // Fetch expired group members by comparing the "historical" group members with that of the current based on the group ids
            var expiredGroupMembers = groupMembersDict.Values.Where(sgm =>
                                            !sgmGroupSpecific.Any(x => x.Id == sgm.Id) &&
                                            sgm.SecurityGroupId != null &&
                                            groupsDict.ContainsKey((Guid)sgm.SecurityGroupId) && 
                                            groupsDict[(Guid)sgm.SecurityGroupId].EntraIdGroupId != null)
                                     .ToList();
            
            _logger.LogDebug("Found {0} expired group memberships to remove", expiredGroupMembers.Count);
            
            foreach (var sgm in expiredGroupMembers)
            {
                var sg = groupsDict[(Guid)sgm.SecurityGroupId];
                _logger.LogDebug("Removing user from security group: {0}, Name: {1}, EntraIdGroupId: {2}", 
                    sg.Id, sg.Name, sg.EntraIdGroupId);
                
                db.Entry(sgm).State = EntityState.Deleted;
                isDirty = true;
            }

            if (isDirty)
            {
                _logger.LogDebug("Changes detected, saving changes to database");
                await db.SaveChangesAsync(identity);
            }
            else
            {
                _logger.LogDebug("No changes to user group memberships needed");
            }
        }

        private async Task EnsureAccessGroupsCreated(EAVDBContext<DynamicContext> db)
        {
            _logger.LogDebug("Ensuring access groups are created. Configured groups: {0}", 
                _options.Value.AccessGroups.Count(kv => !string.IsNullOrEmpty(kv.Value)));
                
            var groups = _options.Value.AccessGroups
                .Where(kv => !string.IsNullOrEmpty(kv.Value))
                .Select(c => c.Key)
                .ToArray();
                
            var existingGroups = await db.Set<TSecurityGroup>()
                .Where(g => groups.Contains(g.Name))
                .ToListAsync();
                
            _logger.LogDebug("Found {0} existing groups out of {1} configured", 
                existingGroups.Count, groups.Length);
                
            var missingGroups = groups.Except(existingGroups.Select(g => g.Name)).ToArray();
            
            foreach (var missingGroup in missingGroups)
            {
                _logger.LogDebug("Creating missing security group: {0} with EntraId: {1}", 
                    missingGroup, _options.Value.AccessGroups[missingGroup]);
                    
                var group = new TSecurityGroup();
                group.Name = missingGroup;
                group.EntraIdGroupId = Guid.Parse(_options.Value.AccessGroups[missingGroup]);
                db.Add(group);

                existingGroups.Add(group);
            }
            
            foreach (var group in existingGroups)
            {
                if (!group.EntraIdGroupId.HasValue)
                {
                    _logger.LogDebug("Updating existing security group: {0} with EntraId: {1}", 
                        group.Name, _options.Value.AccessGroups[group.Name]);
                        
                    group.EntraIdGroupId = Guid.Parse(_options.Value.AccessGroups[group.Name]);
                }
            }
            
            if (missingGroups.Length > 0 || existingGroups.Any(g => !g.EntraIdGroupId.HasValue))
            {
                _logger.LogDebug("Saving security group changes");
                await db.SaveChangesAsync(_frameworkOptions.Value.SystemAdministratorIdentity);
            }
        }

        
    }
}