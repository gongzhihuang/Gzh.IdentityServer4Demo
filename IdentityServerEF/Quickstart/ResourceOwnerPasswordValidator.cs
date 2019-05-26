using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using System.Linq;
using System;
using IdentityModel;

namespace IdentityServerEF.Quickstart
{
    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private UserDbContext _userDbContext;
        public ResourceOwnerPasswordValidator(UserDbContext userContext)
        {
            _userDbContext = userContext;
        }

        public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            //var user = await _myUserManager.FindByNameAsync(context.UserName);
            var user = _userDbContext.Users.Where(x => x.Name == context.UserName && x.Password == context.Password).FirstOrDefault();
            if (user != null)
            {
                context.Result = new GrantValidationResult(
                    subject: user.Name,
                    authenticationMethod: "custom",
                    claims: null);
            }
            else
            {
                context.Result = new GrantValidationResult(
                       TokenRequestErrors.InvalidGrant,
                       "invalid custom credential");
            }
            return;

        }
    }
}
