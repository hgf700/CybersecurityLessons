using aspapp.Services;
using Microsoft.AspNetCore.Mvc;
using static System.Net.Mime.MediaTypeNames;


namespace aspapp.Controllers
{
    public class VigenereCipherController : Controller
    {
        [HttpGet]
        public IActionResult Generate()
        {
            string text = "Hello World";
            string key = "asd";

            string encrypted = VigenereCipher.Encipher(text, key);
            string decrypted = VigenereCipher.Decipher(encrypted, key);

            ViewBag.Input = text;
            ViewBag.Key = key;
            ViewBag.Encrypted = encrypted;
            ViewBag.Decrypted = decrypted;

            return View();
        }
    }
}
