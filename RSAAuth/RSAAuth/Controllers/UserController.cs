﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using NLog;
using RSAAuth.Models;
using RSAAuth.Utils;

namespace RSAAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        [HttpPost("[action]")]
        public ActionResult CreateUser([FromBody] UserModel user)
        {
            try
            {
                UserUtil.CreateUser(user);
                return Ok();
            }
            catch (Exception e)
            {
                Logger.Error(e);
                return StatusCode(500);
            }
        }
    }
}
