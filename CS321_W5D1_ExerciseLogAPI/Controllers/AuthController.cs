using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using CS321_W5D1_ExerciseLogAPI.Core.Models;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;
using CS321_W5D1_ExerciseLogAPI.ApiModels;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System;
using Microsoft.Extensions.Configuration;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CS321_W5D1_ExerciseLogAPI.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _config;

        // TODO: Prep Part 1: add constructor and inject UserManager 
        public AuthController(UserManager<User> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _config = configuration;
        }
        

        // TODO: Prep Part 1: Add a Registration Action (Part 1 of Prep exercise)
        //api/auth/register
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegistrationModel registration)
        {
            var newUser = new User
            {
                UserName = registration.Email,
                Email = registration.Email,
                FirstName = registration.FirstName,
                LastName = registration.LastName
                // note that we do NOT assign password. Instead of a Password property, there is
                // PaswordHashed, which will be assigned when we create the user. It will store
                // the password in a secure form.
            };

            var result = await _userManager.CreateAsync(newUser, registration.Password);
            if (result.Succeeded)
            {
                return Ok(newUser.ToApiModel());
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return BadRequest(ModelState);
        }

        // TODO: Prep Part 2: Add a login action (Part 2 of Prep exercise)
        //api/auth/login
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            IActionResult response = Unauthorized();
            var user = await AuthenticateUserAsync(login.Email, login.Password);

            if(user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        private string GenerateJSONWebToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature);
            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            };

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: credentials);

            return tokenHandler.WriteToken(token);
        }

        private async Task<User> AuthenticateUserAsync(string userName, string password)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if(user != null && await _userManager.CheckPasswordAsync(user, password))
            {
                return user;
            }

            return null; 
        }
    }
}
