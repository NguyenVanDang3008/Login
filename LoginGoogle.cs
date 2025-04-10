using Demo.Model;
using DemoData.Data;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;
using Google.Apis.Http;
using System.Net.Http;

[Route("LoginGoogle")]
public class LoginGoogleController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _config;
    private readonly System.Net.Http.IHttpClientFactory _httpClientFactory;
    public LoginGoogleController(ApplicationDbContext context, IConfiguration config, System.Net.Http.IHttpClientFactory httpClientFactory)
    {
        _context = context;
        _config = config;
        _httpClientFactory = httpClientFactory;
    }


    [HttpGet]
    public IActionResult Index()
    {
        return View("~/Views/Login/Login.cshtml");
    }

    [HttpPost("LoginGoogle")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLogin model)
    {
        Console.WriteLine("Token nhận được từ client: " + model.IdToken);

        if (string.IsNullOrEmpty(model.IdToken))
        {
            return BadRequest(new { message = "Token không được để trống" });
        }

        try
        {
            var validationSettings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { "560463192425-kpde3a3gkqbpgiu7p6t010dvfa3pppai.apps.googleusercontent.com" },
                ForceGoogleCertRefresh = true,
                ExpirationTimeClockTolerance = TimeSpan.FromMinutes(5),
                IssuedAtClockTolerance = TimeSpan.FromMinutes(5)
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(model.IdToken, validationSettings);

            Console.WriteLine($"Token valid từ: {payload.IssuedAtTimeSeconds} đến {payload.ExpirationTimeSeconds}");
            Console.WriteLine($"Thời gian hiện tại: {DateTimeOffset.UtcNow.ToUnixTimeSeconds()}");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == payload.Email);
            bool isNewUser = false;

            if (user == null)
            {
                user = new User
                {
                    Email = payload.Email,
                    Password = "",
                };
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                isNewUser = true;
            }

            string token = GenerateJwtToken(user.Email, "User");

            return Ok(new
            {
                message = "Đăng nhập bằng Google thành công",
                token = token,
                isNewUser = isNewUser,
                email = payload.Email,
                name = payload.Name
            });
        }
        catch (InvalidJwtException ex)
        {
            Console.WriteLine($"Lỗi JWT chi tiết: {ex}");
            return Unauthorized(new
            {
                message = "Token Google không hợp lệ",
                error = ex.Message,
                details = ex.ToString()
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi server: {ex}");
            return StatusCode(500, new
            {
                message = "Lỗi server khi xử lý đăng nhập",
                error = ex.Message
            });
        }
    }
    [HttpPost("LoginFacebook")]
    public async Task<IActionResult> FacebookLogin([FromBody] FacebookLogin data)
    {
        if (data == null || string.IsNullOrEmpty(data.AccessToken))
            return BadRequest(new { message = "Access Token không được để trống" });

        try
        {
            var client = _httpClientFactory.CreateClient();
            var response = await client.GetAsync($"https://graph.facebook.com/me?fields=id,name,email&access_token={data.AccessToken}");

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Lỗi từ Facebook API: {errorContent}");
                return Unauthorized(new
                {
                    message = "Access Token Facebook không hợp lệ",
                    facebookError = errorContent
                });
            }

            var json = await response.Content.ReadAsStringAsync();
            var obj = JObject.Parse(json);
            var email = (string)obj["email"];
            var name = (string)obj["name"];
            var id = (string)obj["id"];

            // Nếu không có email, sử dụng ID Facebook + @facebook.com
            if (string.IsNullOrEmpty(email))
            {
                email = $"{id}@facebook.com";
                Console.WriteLine($"Sử dụng email thay thế: {email}");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            bool isNewUser = false;

            if (user == null)
            {
                user = new User
                {
                    Email = email,
                    Password = "",
                };
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                isNewUser = true;
            }

            string token = GenerateJwtToken(user.Email, "User");

            return Ok(new
            {
                message = "Đăng nhập Facebook thành công",
                token = token,
                isNewUser = isNewUser,
                email = email,
                name = name
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi server: {ex}");
            return StatusCode(500, new
            {
                message = "Lỗi server khi xử lý đăng nhập Facebook",
                error = ex.Message
            });
        }
    }

    private string GenerateJwtToken(string email, string role)
    {
        var jwtSettings = _config.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
        new Claim(ClaimTypes.Email, email),
        new Claim(ClaimTypes.Role, role)
    };

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.Now.AddHours(3),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}
