using System;
using System.IO;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace InfoSec.RestApi
{
    public static class Extensions
    {
        public static Guid GetUserId(this ControllerBase controllerBase)
        {
            return new Guid(controllerBase.HttpContext.User.FindFirstValue("Id"));
        }

        public static byte[] ToByteArray(this IFormFile formFile)
        {
            var stream = formFile.OpenReadStream();
            using var reader = new BinaryReader(stream);
            return reader.ReadBytes((int) formFile.Length);
        }

        public static byte[] ToByteArray(this string str) => Encoding.UTF8.GetBytes(str);

        public static string ToBase64(this byte[] array) => Convert.ToBase64String(array);
    }
}