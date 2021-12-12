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

            return Ok(keyPair.PublicKey);
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
            var number = BitConverter.GetBytes(p*q);
            var eulerFunction = (p - 1) * (q - 1);
            
            //генерация открытого ключа
            var e = (uint) rnd.NextInt64(3, eulerFunction - 1);
            while (GetNod(e, eulerFunction) != 1) 
                e = (uint) rnd.NextInt64(3, eulerFunction - 1);
            var publicKey = new PublicKey {E = BitConverter.GetBytes(e), N = number};

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
            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == dto.KeyPairId);

            if (keyPair is null)
                return NotFound($"Key pair with id {dto.KeyPairId} not found");

            var file = dto.File.ToByteArray();
            byte[] tmpHashA;
            tmpHashA = new MD5CryptoServiceProvider().ComputeHash(file);
            var alicaHash = BitConverter.ToUInt16(tmpHashA);//хэш, который сгенирировала Алиса из полученного документа

            //Проверить подпись
            var e = BitConverter.ToUInt32(keyPair.PublicKey.E);
            var N = BitConverter.ToUInt32(keyPair.PublicKey.N);
            var sing = BitConverter.ToUInt64(dto.Sign); //возможно не правильно вызываю подпись
            var bobHash = binpow(sing, e, N);

            var singIsValid = bobHash == alicaHash;

            return Ok(singIsValid);
        }

        #endregion

        #region Подписывание

        [Authorize]
        [HttpPost("Sign")]
        //[Consumes("multipart/form-data")]
        public async Task<IActionResult> Sign([FromForm] SignDto dto)
        {
            var currentUserId = this.GetUserId();

            var keyPair = await _dbContext.KeyPairs
                .FirstOrDefaultAsync(x => x.Id == dto.KeyPairId && x.OwnerId == currentUserId);

            if (keyPair is null)
                return NotFound($"Key pair with id {dto.KeyPairId} not found for you");
            
            var file = dto.File.ToByteArray();
            byte[] tmpHashB = new MD5CryptoServiceProvider().ComputeHash(file);

            var hashFunction = BitConverter.ToUInt16(tmpHashB);//хэш, который сгенирировал Боб
            var privateKey = BitConverter.ToUInt32(keyPair.PrivateKey);
            var N = BitConverter.ToUInt32(keyPair.PublicKey.N);
            var sign = binpow(hashFunction, privateKey, N);

            return Ok(BitConverter.GetBytes(sign));
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

        private static ulong binpow (ulong a, ulong n, ulong m)
        {
            if (n == 0)
                return 1 % m;
            if (n % 2 == 1)
                return (binpow(a, n - 1, m) * a) % m;
            else
            {
                return binpow((a * a) % m, n / 2, m);
            }
        }
    }
}
