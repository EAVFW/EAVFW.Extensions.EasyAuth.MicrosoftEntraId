using EAVFramework.Authentication;
using EAVFramework.Extensions;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using static IdentityModel.OidcConstants;
using static System.Net.WebRequestMethods;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{

    public class MicrosoftEntraEasyAuthProvider : IEasyAuthProvider
    {
        private readonly IOptions<MicrosoftEntraIdEasyAuthOptions> _options;
        private readonly IHttpClientFactory _clientFactory;

        public string AuthenticationName => "MicrosoftEntraId";

        public HttpMethod CallbackHttpMethod => HttpMethod.Post;

        public bool AutoGenerateRoutes { get; set; } = true;

        public MicrosoftEntraEasyAuthProvider() { }

        public MicrosoftEntraEasyAuthProvider(IOptions<MicrosoftEntraIdEasyAuthOptions> options, IHttpClientFactory clientFactory)
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
            return await Task.FromResult((new ClaimsPrincipal(identity), redirectUri, handleId));
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