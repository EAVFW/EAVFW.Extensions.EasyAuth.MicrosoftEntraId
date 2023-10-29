using EAVFramework.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace EAVFW.Extensions.EasyAuth.MicrosoftEntraId
{
    public static class MicrosoftEntraIdEasyAuthExtensions
    {
        public static AuthenticatedEAVFrameworkBuilder AddMicrosoftEntraIdEasyAuth(this AuthenticatedEAVFrameworkBuilder builder)
        {

            builder.AddAuthenticationProvider<MicrosoftEntraEasyAuthProvider, MicrosoftEntraIdEasyAuthOptions,IConfiguration>((options, config) =>
            {

            });
            return builder;
        }
    }
}