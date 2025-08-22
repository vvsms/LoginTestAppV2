using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Blazored.LocalStorage;

namespace Auth.Client.Blazor.Services
{
    public class ApiAuthService
    {
        private readonly HttpClient _http;
        private readonly ILocalStorageService _storage;

        public ApiAuthService(HttpClient http, ILocalStorageService storage)
        {
            _http = http;
            _storage = storage;
        }

        public async Task<bool> RegisterAsync(string email, string password, string? fullName)
        {
            var dto = new { Email = email, Password = password, FullName = fullName };
            var res = await _http.PostAsync("api/auth/register",
                new StringContent(JsonSerializer.Serialize(dto), Encoding.UTF8, "application/json"));
            return res.IsSuccessStatusCode;
        }

        public async Task<(bool success, string? accessToken, string? refreshToken)> LoginAsync(string email, string password)
        {
            var dto = new { Email = email, Password = password };
            var res = await _http.PostAsync("api/auth/login",
                new StringContent(JsonSerializer.Serialize(dto), Encoding.UTF8, "application/json"));

            if (!res.IsSuccessStatusCode) return (false, null, null);

            var json = await res.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var access = doc.RootElement.GetProperty("accessToken").GetString();
            var refresh = doc.RootElement.GetProperty("refreshToken").GetString();

            // store tokens using local storage
            await _storage.SetItemAsync("accessToken", access);
            await _storage.SetItemAsync("refreshToken", refresh);

            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);

            return (true, access, refresh);
        }

        public async Task LogoutAsync()
        {
            await _storage.RemoveItemAsync("accessToken");
            await _storage.RemoveItemAsync("refreshToken");
            _http.DefaultRequestHeaders.Authorization = null;
        }

        // method to refresh access token using saved refresh token
        public async Task<bool> SilentRefreshAsync()
        {
            var refreshToken = await _storage.GetItemAsync<string>("refreshToken");
            if (string.IsNullOrEmpty(refreshToken)) return false;

            var dto = new { RefreshToken = refreshToken };
            var res = await _http.PostAsync("api/auth/refresh",
                new StringContent(JsonSerializer.Serialize(dto), Encoding.UTF8, "application/json"));

            if (!res.IsSuccessStatusCode) return false;

            var json = await res.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var access = doc.RootElement.GetProperty("accessToken").GetString();
            var refresh = doc.RootElement.GetProperty("refreshToken").GetString();

            await _storage.SetItemAsync("accessToken", access);
            await _storage.SetItemAsync("refreshToken", refresh);

            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
            return true;
        }
    }
}
