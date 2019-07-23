// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerEF.Quickstart
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// 此示例控制器为本地和外部帐户实现典型的登录/注销/设置工作流。
    /// 登录服务封装了与用户数据存储的交互。此数据存储仅在内存中，不能用于生产！
    /// 交互服务为UI提供了一种与IdentityServer通信的方式，用于验证和上下文检索。
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly TestUserStore _users;

        private UserDbContext _userDbContext;

        /// <summary>
        /// 交互服务,提供用于用户界面用于与身份服务器通信的服务
        /// </summary>
        private readonly IIdentityServerInteractionService _interaction;

        /// <summary>
        /// 客户端配置检索
        /// </summary>
        private readonly IClientStore _clientStore;

        /// <summary>
        /// 负责管理支持哪些身份验证方案
        /// </summary>
        private readonly IAuthenticationSchemeProvider _schemeProvider;

        /// <summary>
        /// 事件服务界面
        /// </summary>
        private readonly IEventService _events;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            UserDbContext userContext,
            TestUserStore users = null)
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
            _users = users ?? new TestUserStore(TestUsers.Users);

            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _userDbContext = userContext;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// 登录流程入口点
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            //建立一个模型以便我们知道在登录页面上显示什么
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                //我们只有一个登录选项，它是一个外部提供者
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// 处理用户名/密码登录的回发
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            //检查我们是否在授权请求的上下文中
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            // 用户点击了取消按钮
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    //如果用户取消，则将结果发送回IdentityServer，如同他们拒绝同意一样（即使此客户端不需要同意）。
                    //这将向客户端发送拒绝访问的OIDC错误响应。
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    //我们可以信任Model.ReturnURL，因为GetAuthorizationContextAsync返回非空值
                    if (await _clientStore.IsPkceClientAsync(context.ClientId))
                    {
                        // if the client is PKCE then we assume it's native, so this change in how to
                        // return the response is for better UX for the end user.
                        //如果客户机是pkce，那么我们假设它是本机的，所以如何返回响应的这种更改是为了更好地为最终用户提供UX。
                        return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    //因为我们没有有效的上下文，所以我们只需返回主页
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                // validate username/password against in-memory store
                /*
                if (_users.ValidateCredentials(model.Username, model.Password))
                {
                    var user = _users.FindByUsername(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username));

                    // only set explicit expiration here if user chooses "remember me". 
                    // otherwise we rely upon expiration configured in cookie middleware.
                    AuthenticationProperties props = null;
                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    };

                    // issue authentication cookie with subject ID and username
                    await HttpContext.SignInAsync(user.SubjectId, user.Username, props);

                    if (context != null)
                    {
                        if (await _clientStore.IsPkceClientAsync(context.ClientId))
                        {
                            // if the client is PKCE then we assume it's native, so this change in how to
                            // return the response is for better UX for the end user.
                            return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }
                */

                var user = _userDbContext.Users.Where(x => x.Name == model.Username && x.Password == model.Password).FirstOrDefault();
                if (user != null)
                {
                    //var user = _users.FindByUsername(model.Username);

                    // RaiseAsync 引发指定的事件。
                    // 引发用户登录成功的事件
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Name, user.Id.ToString(), user.Name));

                    // only set explicit expiration here if user chooses "remember me". 
                    // otherwise we rely upon expiration configured in cookie middleware.
                    //仅当用户选择“记住我”时才在此处设置显式过期。
                    //否则，我们依赖于在cookie中间件中配置的过期。
                    AuthenticationProperties props = null; // 用于存储有关身份验证会话的状态值的字典
                    //记住登录
                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,//获取或设置是否跨多个请求持久化身份验证会话
                            //获取或设置身份验证票证过期的时间。 默认30天？
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    };

                    // issue authentication cookie with subject ID and username
                    //颁发具有使用者ID和用户名的身份验证cookie
                    await HttpContext.SignInAsync(user.Id.ToString(), user.Name, props);

                    if (context != null)
                    {
                        if (await _clientStore.IsPkceClientAsync(context.ClientId))
                        {
                            // if the client is PKCE then we assume it's native, so this change in how to
                            // return the response is for better UX for the end user.
                            return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        //用户可能单击了恶意链接-应记录
                        throw new Exception("invalid return URL");
                    }
                }

                //引发登录失败的事件
                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            //出错，表单显示错误内容
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }


        /// <summary>
        /// Show logout page
        /// 显示注销页面
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            //构建一个模型，以便注销页面知道要显示什么
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                //如果从IdentityServer正确验证了注销请求，则我们不需要显示提示，只需直接注销用户即可。
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// 处理注销页回发
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            //构建一个模型，以便注销页面知道要显示什么
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                //删除本地身份验证cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                // 引发注销成功事件
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            //检查是否需要触发上游身份提供程序的注销
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                //构建一个返回URL，以便上游提供程序在用户注销后将重定向回我们。这样我们就可以完成我们的单次注销处理
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                //这将触发重定向到外部提供程序以进行注销
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }



        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/

        /// <summary>
        /// 构建登录模型
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                //这是为了使UI短路，并且只触发一个外部IDP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                //按标识符查找启用的客户端
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        /// <summary>
        /// 构建登录模型
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        /// <summary>
        /// 构建注销模型
        /// </summary>
        /// <param name="logoutId"></param>
        /// <returns></returns>
        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                //如果用户未通过身份验证，则只显示注销页面
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                //自动注销是安全的
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            //显示注销提示。这可以防止用户被另一个恶意网页自动注销的攻击。
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            //获取上下文信息（客户端名称、注销后重定向URI和联合注销的iframe）
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}