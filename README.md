# ApricotFramework.Authentication

[![NuGet](https://img.shields.io/nuget/v/ApricotFramework.Authentication.svg?label=ApricotFramework.Authentication)](https://www.nuget.org/packages/ApricotFramework.Authentication/)
[![NuGet](https://img.shields.io/nuget/v/ApricotFramework.Authentication.AspNetCore.svg?label=ApricotFramework.Authentication.AspNetCore)](https://www.nuget.org/packages/ApricotFramework.Authentication.AspNetCore/)
[![NuGet](https://img.shields.io/nuget/v/ApricotFramework.Authentication.ErrorDefinitions.svg?label=ApricotFramework.Authentication.ErrorDefinitions)](https://www.nuget.org/packages/ApricotFramework.Authentication.ErrorDefinitions/)
[![CI](https://github.com/project-apricot/authentication/actions/workflows/ci.yml/badge.svg)](https://github.com/project-apricot/authentication/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/project-apricot/authentication/blob/main/LICENSE)

Both directions of a microservice's authentication from one settings section: JWT bearer validation for
the requests it serves, and OAuth 2.0 client credentials tokens for the services it calls — discovered,
cached until shortly before they expire, and coalesced so a cold start makes one token request rather
than one per caller.

`ApricotFramework.Authentication` is the **zero-dependency** core, and works in a console or worker host
without ASP.NET Core.

## Install

```bash
dotnet add package ApricotFramework.Authentication.AspNetCore
dotnet add package ApricotFramework.Authentication.ErrorDefinitions   # to answer with problem+json
```

## Usage

```csharp
// Inbound validation and the outbound client, from one section.
builder.Services.AddJwtBearerAuthentication(builder.Configuration);
builder.Services.AddAuthorization();
builder.Services.AddAuthenticationErrorDefinitions();
```

```jsonc
{
  "Authentication": {
    "Authority": "https://idp.example.com",
    "ValidAudiences": [ "orders-api" ],
    "Client": {
      // The secret comes from the environment, as Authentication__Client__ClientSecret.
      "ClientId": "orders-service",
      "Scopes": [ "billing.read" ]
    }
  }
}
```

```csharp
[HttpGet("{id}")]
[BearerAuthorize]
public async Task<Order> Get(string id, CancellationToken cancellationToken)
{
    // Works for a person and for a service alike: Subject is null for a machine token, because a
    // client credentials grant has no resource owner to name.
    var caller = this.HttpContext.GetPrincipal();

    return await this.authenticator.DoAuthenticatedAsync(
        (token, ct) => this.billing.GetAsync(id, token, ct),
        cancellationToken: cancellationToken);
}
```

> **Note.** A token this service could not obtain for an onward call never answers 401 or 403. The
> caller presented a good credential; it is this service that could not present one of its own, so it
> answers 503 when waiting may help and 500 when it will not.

Full documentation at [projectapricot.dev](https://projectapricot.dev).
