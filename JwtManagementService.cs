using Forge.Security.Jwt.Shared.Service;
using Forge.Security.Jwt.Shared.Service.Models;
using Forge.Security.Jwt.Shared.Storage;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Forge.Security.Jwt.Service
{

    /// <summary>Jwt Management Service implementation</summary>
    public class JwtManagementService : IJwtManagementService
    {

        private readonly ConcurrentDictionary<string, JwtRefreshToken> _usersRefreshTokens;  // can store in a database or a distributed cache
        private readonly JwtTokenConfiguration _jwtTokenConfig;
        private readonly IStorage<JwtRefreshToken> _tokenStorage;
        private readonly byte[] _secret;
        private volatile bool _initialized = false;
        private readonly SemaphoreSlim _initGate = new SemaphoreSlim(1, 1);

        /// <summary>Initializes a new instance of the <see cref="JwtManagementService" /> class.</summary>
        /// <param name="jwtTokenConfig">The JWT token configuration.</param>
        /// <param name="tokenStorage">The JWT token persistence storage.</param>
        public JwtManagementService(JwtTokenConfiguration jwtTokenConfig, IStorage<JwtRefreshToken> tokenStorage)
        {
            if (jwtTokenConfig is null) throw new ArgumentNullException(nameof(jwtTokenConfig));
            if (tokenStorage is null) throw new ArgumentNullException(nameof(tokenStorage));

            _jwtTokenConfig = jwtTokenConfig;
            _tokenStorage = tokenStorage;
            _usersRefreshTokens = new ConcurrentDictionary<string, JwtRefreshToken>();
            _secret = Encoding.ASCII.GetBytes(_jwtTokenConfig.Secret);
        }

        /// <summary>Initializes a new instance of the <see cref="JwtManagementService" /> class.</summary>
        /// <param name="jwtTokenConfig">The JWT token configuration.</param>
        /// <param name="tokenStorage">The JWT token persistence storage.</param>
        public JwtManagementService(IOptions<JwtTokenConfiguration> jwtTokenConfig, IStorage<JwtRefreshToken> tokenStorage)
            : this(jwtTokenConfig?.Value, tokenStorage)
        {
        }

        /// <summary>Removes the expired refresh tokens.</summary>
        /// <param name="now">The time before the tokens are expired</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>True, if at least one token removed, otherwise False.</returns>
        public async ValueTask<bool> RemoveExpiredRefreshTokensAsync(DateTime now, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

            List<KeyValuePair<string, JwtRefreshToken>> expiredTokens =
                _usersRefreshTokens
                    .Where(x => x.Value.ExpireAt < now)
                    .ToList();

            foreach (KeyValuePair<string, JwtRefreshToken> expiredToken in expiredTokens)
            {
                _usersRefreshTokens.TryRemove(expiredToken.Key, out _);
                await _tokenStorage.RemoveAsync(expiredToken.Key).ConfigureAwait(false);
            }

            return expiredTokens.Count > 0;
        }

        /// <summary>Removes the refresh token by user name and keys.</summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="secondaryKey">The secondary key.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>True, if at least one token removed, otherwise False.</returns>
        public async ValueTask<bool> RemoveRefreshTokenByUserNameAndKeysAsync(string userName, IEnumerable<JwtKeyValuePair> secondaryKey, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

            List<KeyValuePair<string, JwtRefreshToken>> refreshTokens =
                _usersRefreshTokens
                    .Where(x => x.Value.Username == userName && x.Value.CompareSecondaryKeys(secondaryKey))
                    .ToList();

            foreach (KeyValuePair<string, JwtRefreshToken> refreshToken in refreshTokens)
            {
                _usersRefreshTokens.TryRemove(refreshToken.Key, out _);
                await _tokenStorage.RemoveAsync(refreshToken.Key, cancellationToken).ConfigureAwait(false);
            }

            return refreshTokens.Count > 0;
        }

        /// <summary>Generates a new token.</summary>
        /// <param name="username">The username.
        /// Mandatory.</param>
        /// <param name="claims">The claims.</param>
        /// <param name="now">Indicates, when the token will be activated.</param>
        /// <param name="secondaryKeys">The secondary keys to identify a token.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Jwt access and refresh token</returns>
        public async Task<JwtTokenResult> GenerateTokensAsync(string username, Claim[] claims, DateTime now, IEnumerable<JwtKeyValuePair> secondaryKeys, CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

            bool shouldAddAudienceClaim = string.IsNullOrWhiteSpace(claims?.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Aud)?.Value);
            JwtSecurityToken jwtToken = new JwtSecurityToken(
                _jwtTokenConfig.Issuer,
                shouldAddAudienceClaim ? _jwtTokenConfig.Audience : string.Empty,
                claims,
                notBefore: now,
                expires: now.AddMinutes(_jwtTokenConfig.AccessTokenExpirationInMinutes),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(_secret), SecurityAlgorithms.HmacSha256Signature));
            string accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            JwtRefreshToken refreshToken = new JwtRefreshToken
            {
                Username = username,
                TokenString = GenerateRefreshTokenString(),
                ExpireAt = now.AddMinutes(_jwtTokenConfig.RefreshTokenExpirationInMinutes)
            };

            if (secondaryKeys is not null) refreshToken.SecondaryKeys.AddRange(secondaryKeys);

            _usersRefreshTokens.AddOrUpdate(refreshToken.TokenString, refreshToken, (s, t) => refreshToken);

            await _tokenStorage.SetAsync(refreshToken.TokenString, refreshToken, cancellationToken: cancellationToken).ConfigureAwait(false);

            return new JwtTokenResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.TokenString,
                RefreshTokenExpireAt = refreshToken.ExpireAt
            };
        }

        /// <summary>ValidateAsync the specified access and refresh tokens.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="accessToken">The access token.</param>
        /// <param name="now">The time when the refresh token will be active</param>
        /// <param name="secondaryKeys">The secondary keys.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>True, if the tokens are valid, otherwise False.</returns>
        public async Task<JwtTokenValidationResultEnum> ValidateAsync(
            string refreshToken,
            string accessToken,
            DateTime now,
            IEnumerable<JwtKeyValuePair> secondaryKeys,
            CancellationToken cancellationToken = default)
        {
            await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

            var (principal, jwtToken) = DecodeJwtToken(accessToken);
            if (jwtToken is null)
            {
                return JwtTokenValidationResultEnum.JwtTokenDecodingError;
            }

            if (!jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature))
            {
                return JwtTokenValidationResultEnum.SignatureAlgorithmMismatch;
            }

            if (!_usersRefreshTokens.TryGetValue(refreshToken, out var existingRefreshToken))
            {
                return JwtTokenValidationResultEnum.RefreshTokenNotFound;
            }

            string? userName = principal.Identity?.Name;
            if (existingRefreshToken.Username != userName)
            {
                return JwtTokenValidationResultEnum.UsernameMismatch;
            }

            if (existingRefreshToken.ExpireAt < now)
            {
                return JwtTokenValidationResultEnum.RefreshTokenExpired;
            }

            if (!existingRefreshToken.CompareSecondaryKeys(secondaryKeys))
            {
                return JwtTokenValidationResultEnum.SecondaryKeysMismatch;
            }

            return JwtTokenValidationResultEnum.Valid;
        }

        /// <summary>Generates new access and refresh tokens</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="accessToken">The access token.</param>
        /// <param name="now">The time when the refresh token will be active</param>
        /// <param name="secondaryKeys">The secondary keys to identify the refresh token</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Jwt access and refresh token</returns>
        public async Task<JwtTokenResult> RefreshAsync(string refreshToken, string accessToken, DateTime now, IEnumerable<JwtKeyValuePair> secondaryKeys, CancellationToken cancellationToken = default)
        {
            JwtTokenValidationResultEnum validationResult = await ValidateAsync(refreshToken, accessToken, now, secondaryKeys, cancellationToken).ConfigureAwait(false);
            if (validationResult != JwtTokenValidationResultEnum.Valid)
            {
                throw new SecurityTokenException($"Invalid token: {validationResult.ToString()}");
            }

            var (principal, _) = DecodeJwtToken(accessToken);
            string? userName = principal.Identity?.Name;

            return await GenerateTokensAsync(userName!, principal.Claims.ToArray(), now, secondaryKeys, cancellationToken).ConfigureAwait(false); // need to recover the original claims
        }

        /// <summary>Decodes the JWT token and get back the stored information</summary>
        /// <param name="token">The token.</param>
        /// <returns>ClaimsPrincipal and JwtSecurityToken</returns>
        public (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new SecurityTokenException("Invalid token");
            }

            ClaimsPrincipal principal = new JwtSecurityTokenHandler()
                .ValidateToken(token,
                    new TokenValidationParameters
                    {
                        ValidateIssuer = _jwtTokenConfig.ValidateIssuer,
                        ValidIssuer = _jwtTokenConfig.Issuer,
                        ValidateIssuerSigningKey = _jwtTokenConfig.ValidateIssuerSigningKey,
                        IssuerSigningKey = new SymmetricSecurityKey(_secret),
                        ValidAudience = _jwtTokenConfig.Audience,
                        ValidateAudience = _jwtTokenConfig.ValidateAudience,
                        ValidateLifetime = _jwtTokenConfig.ValidateLifetime,
                        ClockSkew = TimeSpan.FromMinutes(_jwtTokenConfig.ClockSkewInMinutes)
                    },
                    out var validatedToken);

            return (principal, (validatedToken as JwtSecurityToken)!);
        }

        private static string GenerateRefreshTokenString()
        {
            byte[] randomNumber = new byte[32];
            using RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
        {
            if (_initialized) return;                                    // gyors út: ha kész, nincs zárolás

            await _initGate.WaitAsync(cancellationToken).ConfigureAwait(false);           // egyszerre csak egy hívó léphet be
            try
            {
                if (_initialized) return;                                // dupla-ellenőrzés a kapun belül

                IEnumerable<JwtRefreshToken> tokens = await _tokenStorage.GetAsync().ConfigureAwait(false);
                foreach (JwtRefreshToken token in tokens)
                {
                    _usersRefreshTokens.AddOrUpdate(token.TokenString, token, (k, v) => token);
                }

                _initialized = true;                                     // CSAK a teljes feltöltés után billen át
            }
            finally
            {
                _initGate.Release();
            }
        }

    }

}
