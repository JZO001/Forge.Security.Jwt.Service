using Forge.Security.Jwt.Service.Validations;
using Forge.Security.Jwt.Shared.Service;
using Forge.Security.Jwt.Shared.Service.Models;
using Forge.Security.Jwt.Shared.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Forge.Security.Jwt.Service
{

    /// <summary>Service Collection Extension methods</summary>
    public static class ServiceCollectionExtensions
    {

        /// <summary>
        /// Registers the Forge Jwt Server side authentication services.
        /// </summary>
        /// <returns>IServiceCollection</returns>
        public static IServiceCollection AddForgeJwtServerAuthenticationCore(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddSingleton<IValidateOptions<JwtTokenConfiguration>, JwtTokenConfigurationValidation>();
            services.AddOptions<JwtTokenConfiguration>().Bind(configuration.GetRequiredSection(JwtTokenConfiguration.ConfigurationSectionName)).ValidateOnStart();

            return services
                .AddSingleton<IStorage<JwtRefreshToken>, MemoryStorage<JwtRefreshToken>>()
                .AddSingleton<IJwtManagementService, JwtManagementService>()
                .AddHostedService<JwtTokenMaintenanceHostedService>();
        }

    }

}
