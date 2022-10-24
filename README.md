# Forge.Security.Jwt.Service
Forge.Security.Jwt.Service is a server side library that provides JWT (JSON Web Token) based authentication services.


## Installing

To install the package add the following line to you csproj file replacing x.x.x with the latest version number:

```
<PackageReference Include="Forge.Security.Jwt.Service" Version="x.x.x" />
```

You can also install via the .NET CLI with the following command:

```
dotnet add package Forge.Security.Jwt.Service
```

If you're using Visual Studio you can also install via the built in NuGet package manager.


## Usage
To use Forge.Security.Jwt.Service in service / server application check the example below.

```c#

public async Task<LoginResult> Login(string username, string password, IEnumerable<JwtKeyValuePair> secondaryKeys)
{
	await _signInManager.SignOutAsync();

	LoginResult result = new LoginResult();

	bool isExist = false;
	bool isAccountDisabled = false;
	using (DatabaseContext db = DatabaseContext.Create())
	{
		InititalizationAtStartup.IsUserAccountDisabled(db, username, out isExist, out isAccountDisabled);
	}

	if (isExist && !isAccountDisabled)
	{
		result.LoginResponse = new JwtTokenResult();

		User user = await _userManager.FindByNameAsync(username);
		SignInResult signInResult = await _signInManager.PasswordSignInAsync(user, password, false, false);
		result.Succeeded = signInResult.Succeeded;
		result.RequiresTwoFactor = signInResult.RequiresTwoFactor;
		result.IsLockedOut = signInResult.IsLockedOut;
		result.IsNotAllowed = signInResult.IsNotAllowed;

		var claims = new[]
		{
			new Claim(ClaimTypes.Name, username),
			new Claim(ClaimTypes.Role, user.Role),
			new Claim(ClaimTypes.NameIdentifier, user.Id),
			new Claim(ClaimTypes.Surname, user.Surname),
			new Claim(ClaimTypes.GivenName, user.Givenname),
			new Claim(ClaimTypes.Email, user.Email),
		};

		JwtTokenResult jwtResult = _jwtAuthManager.GenerateTokens(username, claims, DateTime.UtcNow, secondaryKeys);
		result.LoginResponse = jwtResult;
	}

	return result;
}

```

About the incoming parameters:
- username and password are the standard user credentials
- secondaryKeys is a set of additional keys or attributes which makes every users as unique as possible on the client side.
	It is not mandatory to use it, but it is recommended to put additional info, like IP address and/or user-agent, etc.

You can find a full reference implementation in project "Forge.Yoda". Please feel free to check the project in my repositories.
In the solution, "Forge.Yoda.Services.Authentication" is what you are looking for.


Please also check the following projects in my repositories:
- Forge.Yoda
- Forge.Security.Jwt.Service
- Forge.Security.Jwt.Service.Storage.SqlServer
- Forge.Security.Jwt.Client
- Forge.Security.Jwt.Client.Storage.Browser
- Forge.Wasm.BrowserStorages
- Forge.Wasm.BrowserStorages.NewtonSoft.Json
