using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using System.Linq;
using System;
using IdentityModel;
using System.Security.Claims;
using IdentityServerEF.Models;

namespace IdentityServerEF.Quickstart
{
    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private UserDbContext _userDbContext;
        public ResourceOwnerPasswordValidator(UserDbContext userContext)
        {
            _userDbContext = userContext;
        }

        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            //var user = await _myUserManager.FindByNameAsync(context.UserName);
            var user = _userDbContext.Users.Where(x => x.Name == context.UserName && x.Password == context.Password).FirstOrDefault();
            if (user != null)
            {
                context.Result = new GrantValidationResult(
                    subject: user.Id.ToString(),
                    authenticationMethod: "custom",
                    claims: GetUserClaims(user)
                );
            }
            else
            {
                context.Result = new GrantValidationResult(
                       TokenRequestErrors.InvalidGrant,
                       "invalid custom credential");
            }
            return Task.CompletedTask;

        }

        //可以根据需要设置相应的Claim
        private Claim[] GetUserClaims(User user)
        {
            return new Claim[]
            {
            new Claim(JwtClaimTypes.Id, user.Id.ToString()),
            new Claim(JwtClaimTypes.Name,user.Name),
            // new Claim(JwtClaimTypes.GivenName, "jack"),
            // new Claim(JwtClaimTypes.FamilyName, "jack"),
            // new Claim(JwtClaimTypes.Email, "734924401@qq.com"),
            new Claim(JwtClaimTypes.Role,user.Role)
            };
        }
    }
}
