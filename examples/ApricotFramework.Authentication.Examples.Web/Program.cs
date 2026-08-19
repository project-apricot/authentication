using ApricotFramework.Authentication.AspNetCore.Extensions;
using ApricotFramework.Authentication.ErrorDefinitions.Extensions;
using ApricotFramework.ErrorDefinitions.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// The host owns error handling; the libraries only contribute to it.
builder.Services.AddErrorDefinitions();

// One call: the tokens this service accepts and the credentials it calls with come from one section.
builder.Services.AddJwtBearerAuthentication(builder.Configuration);
builder.Services.AddAuthorization();

// Without this a rejected request answers 401 with an empty body, and a token this service could not
// obtain for an onward call answers 500 with no indication of whose fault it was.
builder.Services.AddAuthenticationErrorDefinitions();

var app = builder.Build();

app.UseExceptionHandler();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
