using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using IdentityServerEF.Quickstart;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using IdentityServerEF;
using IdentityServerEF.Models;
using Microsoft.AspNetCore.Identity;

using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.HttpOverrides;
using IdentityServer4.Validation;

namespace IdentityServerEF
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
            string userConnectionString = Configuration.GetSection("userConnectionString").Value;
            services.AddDbContext<UserDbContext>(options => options.UseMySql(userConnectionString));

            // string connectionString = Configuration.GetSection("identityDataConnectionString").Value;
            // var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            // services.AddDbContext<ApplicationDbContext>(options =>
            //     options.UseMySql(connectionString));

            // services.AddIdentity<ApplicationUser, ApplicationRole>()
            //     .AddEntityFrameworkStores<ApplicationDbContext>()
            //     .AddDefaultTokenProviders();

            // //配置Authtication中间件 ,基于数据库配置
            // services.AddIdentityServer(options => options.Authentication.CookieAuthenticationScheme = "Cookies")
            //     .AddDeveloperSigningCredential()
            //     .AddConfigurationStore(options =>
            //     {
            //         options.ConfigureDbContext = builder =>
            //            builder.UseMySql(connectionString,
            //            sql => sql.MigrationsAssembly(migrationsAssembly));
            //     })
            //     .AddOperationalStore(options =>
            //     {
            //         options.ConfigureDbContext = builder =>
            //             builder.UseMySql(connectionString,
            //             sql => sql.MigrationsAssembly(migrationsAssembly));

            //         // this enables automatic token cleanup. this is optional.
            //         options.EnableTokenCleanup = true;
            //         options.TokenCleanupInterval = 30;
            //     })
            //     .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>();

            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                // .AddTestUsers(Config.GetUsers());
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .AddProfileService<ProfileService>();

            services.AddAuthentication("Bearer")
                .AddCookie("Cookies")
                .AddJwtBearer("Bearer", options =>
                {
                    //identityserver4 地址 也就是本项目地址
                    options.Authority = "http://localhost:5000";
                    options.RequireHttpsMetadata = false;
                    options.Audience = "api1";
                });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // InitializeDatabase(app);

            app.UseStaticFiles();

            app.UseIdentityServer();

            app.UseMvcWithDefaultRoute();
        }

        /// <summary>
        /// 初始化数据库
        /// </summary>
        /// <param name="app"></param>
        private void InitializeDatabase(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();
                if (!context.Clients.Any())
                {
                    foreach (var client in Config.GetClients())
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in Config.GetIdentityResources())
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.GetApiResources())
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
            }
        }
    }
}
