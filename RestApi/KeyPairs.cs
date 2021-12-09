using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using InfoSec.Entities;
using InfoSec.RestApi.Dtos.Input;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

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

            return Ok(keyPair.PrivateKey.ToBase64());
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

            return Ok(keyPair.PublicKey.ToBase64());
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
        public async Task<IActionResult> Post(AddKeyPairDto dto)
        {
            // Todo: проверить ключи на соответствие друг другу

            var pair = new KeyPair
            {
                Id = Guid.NewGuid(),
                Name = dto.Name,
                PublicKey = dto.PublicKey,
                PrivateKey = dto.PrivateKey,
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
            var primeNumbers = SieveEratosthenes(1000);
            var rnd = new Random();
            var p = primeNumbers.ElementAt(rnd.Next() % primeNumbers.Count);
            var q = primeNumbers.ElementAt(rnd.Next() % primeNumbers.Count);
            var n = p * q; //надо передавать вместе с открыты ключом
            var eulerFunction = (p - 1) * (q - 1);
            
            //генерация открытого ключа
            var e = (uint) rnd.NextInt64(3, eulerFunction - 1);
            while (GetNod(e, eulerFunction) != 1) 
                e = (uint) rnd.NextInt64(3, eulerFunction - 1);
            var publicKey = BitConverter.GetBytes(e);

            //генерация закрытого ключа
            var privateKey = BitConverter.GetBytes(GetPrivateKey(e, eulerFunction));

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
            var sign = dto.Sign;

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
            // На вход должена поступать хэш-функция сообщения
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

        private static List<uint> SieveEratosthenes(uint n)
        {
            var numbers = new List<uint>();
            //заполнение списка числами от 2 до n-1
            for (var i = 2u; i < n; i++)
            {
                numbers.Add(i);
            }

            for (var i = 0; i < numbers.Count; i++)
            {
                for (var j = 2u; j < n; j++)
                {
                    //удаляем кратные числа из списка
                    numbers.Remove(numbers[i] * j);
                }
            }
            return numbers;
        }

        private static uint GetNod(uint a, uint b)
        {
            if (a == 0) return b;

            var min = Math.Min(a, b);
            var max = Math.Max(a, b);
            //вызываем метод с новыми аргументами
            return GetNod(max % min, min);
        }

        private static uint GetPrivateKey(uint a, uint m)
        {
            var u1 = m;
            var u2 = 0u;
            var v1 = a;
            var v2 = 1u;
            while (v1 != 0)
            {
                var q = u1 / v1;
                var t1 = u1 - q * v1;
                var t2 = u2 - q * v2;
                u1 = v1;
                u2 = v2;
                v1 = t1;
                v2 = t2;
            }

            return (u2 + m) % m;
        }
    }
}
