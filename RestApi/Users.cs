using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using InfoSec.Entities;
using InfoSec.RestApi.Dtos.Input;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace InfoSec.RestApi
{
    [ApiController] [Route("api/[controller]")]
    public class Users : ControllerBase
    {
        #region Конструктор и зависимости

        private readonly AppDbContext _dbContext;

        public Users(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        #endregion
        
        #region Регистрация пользователя

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto dto)
        {
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Login == dto.Login);
            if (existedUser is { })
                return Conflict("User with same login already existed");
            
            // Todo: Проверить логин по длине, формату
            
            // Todo: Проверить пароль

            var user = new User
            {
                Id = Guid.NewGuid(),
                Login = dto.Login,
                Password = dto.Password
            };

            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            var identity = GetIdentityFromUser(user);
            await HttpContext.SignInAsync(new ClaimsPrincipal(identity));
            
            return Ok(new
            {
                user.Id,
                user.Login
            });
        }

        #endregion

        #region Аутентификация пользователя

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginUserDto dto)
        {
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => 
                x.Login == dto.Login
                && x.Password == dto.Password);

            if (existedUser is null)
                return Conflict("Login-password pair is incorrect");

            var identity = GetIdentityFromUser(existedUser);
            await HttpContext.SignInAsync(new ClaimsPrincipal(identity));
            
            return Ok(new
            {
                existedUser.Id,
                existedUser.Login
            });
        }

        #endregion

        #region Сброс аутентификации

        [Authorize]
        [HttpGet("Logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return Ok();
        }

        #endregion
        
        private ClaimsIdentity GetIdentityFromUser(User user)
        {
            var claims = new List<Claim>
            {
                new ("Id", user.Id.ToString()),
                new ("Login", user.Login),
            };

            var identity = new ClaimsIdentity(claims,"User");
            
            return identity;
        }
    }
}