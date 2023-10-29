using EAVFramework.Authentication;
using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using static IdentityModel.OidcConstants;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{

    public class MicrosoftEntraEasyAuthProvider : IEasyAuthProvider
    {
        private readonly IOptions<MicrosoftEntraIdEasyAuthOptions> _options;

        public string AuthenticationName => "MicrosoftEntraId";

        public HttpMethod CallbackHttpMethod => HttpMethod.Post;

        public bool AutoGenerateRoutes { get; set; } = true;

        public MicrosoftEntraEasyAuthProvider() { }

        public MicrosoftEntraEasyAuthProvider(IOptions<MicrosoftEntraIdEasyAuthOptions> options)
        {
            _options = options ?? throw new System.ArgumentNullException(nameof(options));
        }

        public async Task OnAuthenticate(HttpContext httpcontext, string handleId, string redirectUrl)
        {
            var email = httpcontext.Request.Query["email"].FirstOrDefault();
            var redirectUri = httpcontext.Request.Query["redirectUri"].FirstOrDefault();

            //  var url =$"{oauthEndpoint}"
            var ru = new RequestUrl(_options.Value.AuthorizationUrl);
         
             //var authUri = ru.CreateAuthorizeUrl(_options.Value.ClientI
             //  responseType: ResponseTypes.Code,
             //  redirectUri: _options.Value.RedirectUri,
             //  responseMode: ResponseModes.FormPost ,
               
             // // extra: new Parameters { { "consentId", provider.ExternalId } },
             //  //  codeChallenge: challenge,
             //  //  nonce: nonce,
             //  //    responseMode: ResponseModes.FormPost,
             // //scope: "payments:inbound payments:outbound accounts offline_access",

             //  state: handleId);
          
           
        }

        public Task<(ClaimsPrincipal, string, string)> OnCallback(HttpContext httpcontext)
        {
            throw new System.NotImplementedException();
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