using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerEF.Controllers
{
    /// <summary>
    /// 测试
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        [HttpGet("adm")]
        [Authorize(Roles = "admin")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }

        [HttpGet("admm")]
        [Authorize(Roles = "adminn,adminnn")]
        public ActionResult<IEnumerable<string>> Gett()
        {
            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }
    }
}