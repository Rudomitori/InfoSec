using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using InfoSec.Entities;
using InfoSec.RestApi.Dtos.Input;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;

namespace InfoSec.RestApi
{
    [ApiController] [Route("api/[controller]")]
    public class KeyPairs : ControllerBase
    {
        #region Конструктор и зависимости

        private readonly AppDbContext _dbContext;

        public KeyPairs(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        #endregion

        #region Получение списка ключей

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var currentUserId = new Guid(HttpContext.User.FindFirstValue("Id"));

            var keyPairs = await _dbContext.KeyPairs
                .Where(x => x.OwnerId == currentUserId)
                .ToListAsync();

            var dtos = keyPairs.Select(x => new
            {
                x.Id,
                x.Name
            });

            return Ok(dtos);
        }

        #endregion

        #region Получение приватного ключа

        [Authorize]
        [HttpGet("{id:guid}/PrivateKey")]
        public async Task<IActionResult> GetPrivateKey(Guid id)
        {
            var currentUserId = new Guid(HttpContext.User.FindFirstValue("Id"));

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {id} not found for you");

            return File(keyPair.PrivateKey,
                "text/plain",
                $"{keyPair.Name}.ppk");
        }

        #endregion
        
        #region Получение публичного ключа

        [Authorize]
        [HttpGet("{id:guid}/PublicKey")]
        public async Task<IActionResult> GetPublicKey(Guid id)
        {
            var currentUserId = new Guid(HttpContext.User.FindFirstValue("Id"));

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {id} not found for you");

            return File(keyPair.PublicKey,
                "text/plain",
                $"{keyPair.Name}.pub");
        }

        #endregion

        #region Переименование пары ключей

        [Authorize]
        [HttpPatch("{id:guid}/Name")]
        public async Task<IActionResult> RenameKeyPair(
            [BindRequired, FromRoute] Guid id,
            [BindRequired, FromBody] string name)
        {
            var currentUserId = new Guid(HttpContext.User.FindFirstValue("Id"));

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {id} not found for you");

            keyPair.Name = name;
            _dbContext.KeyPairs.Update(keyPair);
            await _dbContext.SaveChangesAsync();

            return Ok();
        }

        #endregion

        #region Добавление пары ключей

        [Authorize]
        [HttpPost]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> Post([FromForm] AddKeyPairDto dto)
        {
            var publicKey = dto.PublicKey.ToByteArray();
            var privateKey = dto.PrivateKey.ToByteArray();
            
            // Todo: проверить ключи на соответствие друг другу
            
            var pair = new KeyPair
            {
                Id = Guid.NewGuid(),
                Name = dto.Name,
                PublicKey = publicKey,
                PrivateKey = privateKey,
                OwnerId = this.GetUserId()
            };

            _dbContext.KeyPairs.Add(pair);
            await _dbContext.SaveChangesAsync();

            return Ok(new
            {
                pair.Id,
                pair.Name,
                pair.OwnerId
            });
        }

        #endregion

        #region Создание пары ключей

        [Authorize]
        [HttpPost("Create")]
        public async Task<IActionResult> Create()
        {
            // Todo: Сгенерировать пару ключей
            throw new NotImplementedException();

            var publicKey = Encoding.UTF8.GetBytes("Some public key");
            var privateKey = Encoding.UTF8.GetBytes("Some private key");
            
            var pair = new KeyPair
            {
                Id = Guid.NewGuid(),
                Name = $"New key pair.{DateTime.UtcNow}",
                PublicKey = publicKey,
                PrivateKey = privateKey,
                OwnerId = this.GetUserId()
            };

            _dbContext.KeyPairs.Add(pair);
            await _dbContext.SaveChangesAsync();

            return Ok(new
            {
                pair.Id,
                pair.Name,
                pair.OwnerId
            });
        }

        #endregion

        #region Удаление пары ключей

        [Authorize]
        [HttpDelete("{id:guid}")]
        public async Task<IActionResult> Delete([BindRequired] Guid id)
        {
            var currentUserId = this.GetUserId();

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {id} not found for you");

            _dbContext.KeyPairs.Remove(keyPair);
            await _dbContext.SaveChangesAsync();

            return Ok();
        }

        #endregion

        #region Проверка подписи

        [Authorize]
        [HttpPost("CheckSign")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> CheckSign([FromForm] CheckSignDto dto)
        {
            var currentUserId = this.GetUserId();

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == dto.KeyPairId && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {dto.KeyPairId} not found for you");

            var file = dto.File.ToByteArray();
            var sign = dto.SignFile.ToByteArray();
            
            // Todo: Проверить подпись
            throw new NotImplementedException();

            var singIsValid = true;
            
            return Ok(singIsValid);
        }

        #endregion

        #region Подписывание
        
        [Authorize]
        [HttpPost("Sign")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> Sign([FromForm] SignDto dto)
        {
            var currentUserId = this.GetUserId();

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == dto.KeyPairId && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {dto.KeyPairId} not found for you");

            var file = dto.File.ToByteArray();
            
            // Todo: Сгенерировать подпись
            throw new NotImplementedException();
            
            // Сгенерированную подпись нужно преобразовать в
            // массив байт для отправки
            byte[] signFile = Encoding.UTF8.GetBytes("Trust me");

            return File(signFile,
                "text/plain",
                $"{dto.File.Name}.sig");
        }
        
        #endregion
    }
}