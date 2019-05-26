using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MvcClientHybrid
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            // 关闭JWT Claim类型映射，以允许常用的Claim（例如'sub'和'idp'）通过
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            //添加身份认证服务
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "MvcClientHybridCookies"; //用Cookie在本地登陆
                options.DefaultChallengeScheme = "oidc"; //使用OpenID Connect协议
            })
                .AddCookie("MvcClientHybridCookies")
                .AddOpenIdConnect("oidc", options =>
                {
                    options.SignInScheme = "MvcClientHybridCookies";
                    options.Authority = "http://localhost:5000"; //信任的IdentityServer地址
                    options.RequireHttpsMetadata = false;

                    options.ClientId = "mvc2";
                    options.ClientSecret = "secret";
                    options.ResponseType = "code id_token"; //表示使用混合流程，通过浏览器返回身份令牌

                    options.SaveTokens = true; //在Cookie中保留IdentityServer颁发的令牌
                    options.GetClaimsFromUserInfoEndpoint = true;

                    options.Scope.Add("api1");
                    options.Scope.Add("offline_access");
                    options.ClaimActions.MapJsonKey("website", "website");
                });


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseAuthentication();

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
