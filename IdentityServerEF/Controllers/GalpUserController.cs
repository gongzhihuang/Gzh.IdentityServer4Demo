using System;
using System.Collections.Generic;
using System.Linq;
using IdentityServerEF.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerEF.Controllers
{
    [Route("api/[controller]")]
    public class GalpUserController : Controller
    {

        private UserDbContext _userDbContext;

        public GalpUserController(UserDbContext userContext)
        {
            _userDbContext = userContext;
        }

        [HttpGet("get")]
        public string Get()
        {
            return "hello";
        }

        /// <summary>
        /// 注册
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("Regist")]
        public ActionResult<ApiResponse<UserViewModel>> Regist(User user)
        {
            var result = new ApiResponse<UserViewModel>();
            try
            {
                if (string.IsNullOrEmpty(user.Name) || string.IsNullOrEmpty(user.Password))
                {
                    result.Code = 500;
                    result.Message = "注册失败,name和password不能为空";
                    return result;
                }

                var existUser = _userDbContext.Users.Where(x => x.Name == user.Name).FirstOrDefault();
                if (null != existUser)
                {
                    result.Code = 500;
                    result.Message = "注册失败，用户名已存在";
                    return result;
                }

                _userDbContext.Add(user);
                int isSuccessed = _userDbContext.SaveChanges();
                if (isSuccessed > 0)
                {
                    UserViewModel userViewModel = new UserViewModel();
                    userViewModel.Name = user.Name;
                    userViewModel.Id = user.Id;
                    result.Result = userViewModel;
                    result.Message = "注册成功";
                }
                else
                {
                    result.Code = 500;
                    result.Message = "注册失败";
                }
            }
            catch (Exception ex)
            {
                result.Code = 500;
                result.Message = ex.InnerException?.Message ?? ex.Message;
            }
            return result;
        }
    }
}