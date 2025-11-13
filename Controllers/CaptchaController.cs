using Microsoft.AspNetCore.Mvc;
using OpenQA.Selenium.BiDi.Modules.BrowsingContext;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace aspapp.Controllers
{
    public class CaptchaController : Controller
    {
        [HttpGet]
        public IActionResult Generate()
        {
            string code = new Random().Next(1000, 9999).ToString();
            HttpContext.Session.SetString("CaptchaCode", code);

            using var bmp = new Bitmap(100, 40);
            using var g = Graphics.FromImage(bmp);
            g.Clear(Color.White);
            using var font = new Font("Arial", 20, FontStyle.Bold);
            g.DrawString(code, font, Brushes.Black, 10, 5);

            using var ms = new MemoryStream();
            bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
            return File(ms.ToArray(), "image/png");
        }
    }
}
