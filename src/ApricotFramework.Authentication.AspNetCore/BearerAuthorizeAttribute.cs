using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace ApricotFramework.Authentication.AspNetCore;

/// <summary>
/// Requires a bearer token, whatever the host's default scheme happens to be.
/// </summary>
/// <remarks>
/// Naming the scheme is the point: a service that later adds cookies for a management UI would
/// otherwise silently start accepting one on its API endpoints.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class BearerAuthorizeAttribute : AuthorizeAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BearerAuthorizeAttribute"/> class.
    /// </summary>
    public BearerAuthorizeAttribute()
    {
        this.AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme;
    }
}
