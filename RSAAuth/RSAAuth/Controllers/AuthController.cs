using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using NLog;
using RSAAuth.Utils;

namespace RSAAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        // Get the server RSA public key.
        [HttpGet("[action]")]
        public ActionResult<string> GetGlobalPublicKey()
        {
            return Ok(RsaUtil.GetRsaKey(false));
        }

        // GET user public RSA key
        [HttpGet("[action]")]
        public ActionResult<string> GetUserPublicKey(int id)
        {
            return Ok(RsaUtil.GetRsaKey(false));
        }
        
        [HttpGet("[action]")]
        public ActionResult<string> Encrypt(string str)
        {
            return Ok(RsaUtil.Encrypt(str));
        }

        [HttpGet("[action]")]
        public ActionResult<string> Decrypt(string str)
        {
            return Ok(RsaUtil.Decrypt(str));
        }
    }
}
