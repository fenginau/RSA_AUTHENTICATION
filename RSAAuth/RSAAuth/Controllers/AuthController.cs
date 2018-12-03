using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NLog;
using RSAAuth.Models;
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
            return Ok(RsaUtil.GetRsaKeyString(false));
        }

        // GET user public RSA key
        [HttpGet("[action]")]
        public ActionResult<string> GetUserPublicKey()
        {
            try
            {
                return Ok(RsaUtil.GetRsaKey(false));
            }
            catch (Exception e)
            {
                Logger.Error(e);
                return StatusCode(500);
            }
        }

        [HttpPost("[action]")]
        public ActionResult<string> RequestSignin([FromBody] SigninRequestModel signinRequest)
        {
            try
            {
                return Ok(UserUtil.ProcessSigninRequest(signinRequest));
            }
            catch (KeyNotFoundException ke)
            {
                return NotFound(ke.Message);
            }
            catch (Exception e)
            {
                Logger.Error(e);
                return StatusCode(500, e.Message);
            }
        }

        [HttpPost("[action]")]
        public ActionResult<string> Signin([FromBody] SigninRequestModel signinRequest)
        {
            try
            {
                return Ok(UserUtil.Signin(signinRequest));
            }
            catch (KeyNotFoundException ke)
            {
                return NotFound(ke.Message);
            }
            catch (Exception e)
            {
                Logger.Error(e);
                return StatusCode(500, e.Message);
            }
        }

        // test only
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

        [HttpGet("[action]"), Authorize(Roles = "user,admin")]
        public ActionResult<string> GetTest()
        {
            return Ok(RsaUtil.GetRsaKey(false));
        }

    }
}
