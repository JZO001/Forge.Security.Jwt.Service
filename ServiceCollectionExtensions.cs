using Forge.Security.Jwt.Shared.Service;
using Forge.Security.Jwt.Shared.Service.Models;
using Forge.Security.Jwt.Shared.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace Forge.Security.Jwt.Service
{

    /// <summary>Service Collection Extension methods</summary>
    public static class ServiceCollectionExtensions
    {

        /// <summary>
        /// Registers the Forge Jwt Server side authentication services.
        /// </summary>
        /// <returns>IServiceCollection</returns>
        public static IServiceCollection AddForgeJwtServerAuthenticationCore(this IServiceCollection services)
        {
            return services
                .AddSingleton<IStorage<JwtRefreshToken>, MemoryStorage<JwtRefreshToken>>()
                .AddSingleton<IJwtManagementService, JwtManagementService>()
                .AddHostedService<JwtTokenMaintenanceHostedService>();
        }

    }

}
