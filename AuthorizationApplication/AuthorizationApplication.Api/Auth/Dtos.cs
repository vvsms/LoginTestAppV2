namespace AuthorizationApplication.Api.Auth
{

    public record RegisterRequest(string Email, string Password);
    public record LoginRequest(string Email, string Password);
    public record AuthResponse(string AccessToken, DateTime ExpiresUtc);
}
