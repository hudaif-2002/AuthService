using Microsoft.EntityFrameworkCore;
using AuthService.Data;
using AuthService.Services;
using AuthService.DTOs;
using AuthService.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Database
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? builder.Configuration["DATABASE_URL"];

if (!string.IsNullOrEmpty(connectionString))
{
    // Convert Railway/Neon URI to connection string if needed
    if (connectionString.StartsWith("postgres://") || connectionString.StartsWith("postgresql://"))
    {
        connectionString = ConvertUriToNpgsql(connectionString);
    }
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(connectionString));
}

builder.Services.AddScoped<JwtService>();

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment() || app.Environment.IsProduction())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowAll");

// Create database
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    db.Database.EnsureCreated();
}

// Routes
app.MapGet("/", () => new { service = "AuthService", version = "1.0", status = "running" });

app.MapPost("/auth/register", async (RegisterRequest request, AuthDbContext db, JwtService jwtService) =>
{
    // Validate input
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        return Results.BadRequest(new { error = "Email and password are required" });

    // Check if user exists
    if (await db.Users.AnyAsync(u => u.Email == request.Email))
        return Results.Conflict(new { error = "User already exists" });

    // Hash password
    var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

    // Create user
    var user = new User
    {
        Email = request.Email,
        PasswordHash = passwordHash,
        FullName = request.FullName,
        CreatedAt = DateTime.UtcNow,
        IsActive = true
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    // Generate token
    var token = jwtService.GenerateToken(user.Id, user.Email, user.FullName);

    return Results.Created($"/users/{user.Id}", new AuthResponse(token, user.Email, user.FullName));
});

app.MapPost("/auth/login", async (LoginRequest request, AuthDbContext db, JwtService jwtService) =>
{
    // Find user
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
    if (user == null)
        return Results.Unauthorized();

    // Verify password
    if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        return Results.Unauthorized();

    // Update last login
    user.LastLoginAt = DateTime.UtcNow;
    await db.SaveChangesAsync();

    // Generate token
    var token = jwtService.GenerateToken(user.Id, user.Email, user.FullName);

    return Results.Ok(new AuthResponse(token, user.Email, user.FullName));
});

app.MapGet("/auth/validate", (HttpContext context) =>
{
    // Simple endpoint to check if token is valid
    // TodoService can call this to validate tokens
    var authHeader = context.Request.Headers.Authorization.ToString();
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        return Results.Unauthorized();

    // In real app, you'd decode and validate the JWT here
    return Results.Ok(new { valid = true, message = "Token is valid" });
});

app.Run();

// Convert PostgreSQL URI to Npgsql key-value format (same as TodoApi)
static string ConvertUriToNpgsql(string uriString)
{
    // Remove query parameters for parsing
    var uriWithoutQuery = uriString.Split('?')[0];
    var uri = new Uri(uriWithoutQuery);
    var userInfo = uri.UserInfo.Split(':');

    // Default to port 5432 if not specified
    var port = uri.Port > 0 ? uri.Port : 5432;

    var connectionString = $"Host={uri.Host};Port={port};Database={uri.AbsolutePath.TrimStart('/')};Username={userInfo[0]};Password={userInfo[1]}";

    // Add SSL mode from query string if present
    if (uriString.Contains("sslmode=require"))
    {
        connectionString += ";SSL Mode=Require;Trust Server Certificate=true";
    }

    return connectionString;
}
