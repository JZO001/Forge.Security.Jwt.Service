using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Linq;

namespace Forge.Security.Jwt.Service.Validations
{

    /// <summary>Jwt Token Configuration validator</summary>
    public class JwtTokenConfigurationValidation : IValidateOptions<JwtTokenConfiguration>
    {

        /// <summary>Validates a specific named options instance (or all when name is null).</summary>
        /// <param name="name">The name of the options instance being validated.</param>
        /// <param name="options">The options instance.</param>
        /// <returns>The <see cref="T:Microsoft.Extensions.Options.ValidateOptionsResult">ValidateOptionsResult</see> result.</returns>
        public ValidateOptionsResult Validate(string name, JwtTokenConfiguration options)
        {
            List<string> errors = new List<string>();

            if (string.IsNullOrWhiteSpace(options.Secret))
            {
                errors.Add($"{nameof(options.Secret)} is required.");
            }

            if (string.IsNullOrWhiteSpace(options.Issuer))
            {
                errors.Add($"{nameof(options.Issuer)} is required.");
            }

            if (string.IsNullOrWhiteSpace(options.Audience))
            {
                errors.Add($"{nameof(options.Audience)} is required.");
            }

            if (options.AccessTokenExpirationInMinutes < 1)
            {
                errors.Add($"{nameof(options.AccessTokenExpirationInMinutes)} must be greater than zero.");
            }

            if (options.RefreshTokenExpirationInMinutes < 1)
            {
                errors.Add($"{nameof(options.RefreshTokenExpirationInMinutes)} must be greater than zero.");
            }

            return errors.Any() ? ValidateOptionsResult.Fail(string.Join(";", errors)) : ValidateOptionsResult.Success;
        }

    }

}
