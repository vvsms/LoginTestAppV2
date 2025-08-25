namespace AuthorizationApplication.Api.Auth
{
    public class JwtSettings
    {
        public string Issuer { get; set; } = "AuthorizationApplication";
        public string Audience { get; set; } = "AuthorizationApplication.Client";
        public string Key { get; set; } = "CHANGE_THIS_DEVELOPMENT_KEY___MIN_32_CHARS"; // replace for prod!
        public int AccessTokenMinutes { get; set; } = 15;      // short-lived
        public int RefreshTokenDays { get; set; } = 7;         // rotate frequently
        public bool IssueRefreshTokenCookie { get; set; } = true; // cookie for browsers
        public bool ReturnRefreshTokenInBody { get; set; } = true; // useful for Flutter/mobile
    }
}