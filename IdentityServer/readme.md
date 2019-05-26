# IdentityServer

## ClientCredentials 客户端授权模式

1.安装 IdentityServer4 Nuget包

2.修改host为 http://localhost:5000

3.添加配置文件 Config.cs

```

public class Config
{
    public static IEnumerable<IdentityResource> GetIdentityResources()
    {
        return new IdentityResource[]
        {
            new IdentityResources.OpenId()
        };
    }

    public static IEnumerable<ApiResource> GetApiResources()
    {
        return new List<ApiResource>
        {
            new ApiResource("api1", "this is ResourcesApi")
        };
    }

    public static IEnumerable<Client> GetClients()
    {
        return new List<Client>
        {
            new Client
            {
                ClientId = "client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets =
                {
                    new Secret("secret".Sha256())
                },

                AllowedScopes = { "api1" }
            }
        };
    }
}

```

4.配置IdentityServer
	在Startup.cs文件中
	```
	public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddInMemoryIdentityResources(Config.GetIdentityResources());
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseIdentityServer();
        }
    }

	```

5.在浏览器中访问 http://localhost:5000/.well-known/openid-configuration
	至此，ClientCredentials授权模式的identityserver已经配置好

6.新建一个ResourceApi项目,host为：http://localhost:5001 ,这是受保护的api资源

修改 ValuesController
```
	[Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        [Authorize]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }
    }

```

7.给ResourceApi这个项目添加验证中间件和配置DI

	作用就是验证令牌

修改Startup.cs
```
	public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvcCore()
                .AddAuthorization()
                .AddJsonFormatters();

            services.AddAuthentication("Bearer")
                .AddJwtBearer("Bearer", options =>
                {
                    options.Authority = "http://localhost:5000";
                    options.RequireHttpsMetadata = false;

                    options.Audience = "api1";
                });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseAuthentication();
            app.UseMvc();
        }
    }

```

8.新建一个ConsoleClient客户端，在这个客户端去请求受保护的ResourceApi
	修改Program.cs中

```
	class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            var client = new HttpClient();
            var disco = client.GetDiscoveryDocumentAsync("http://localhost:5000").Result;
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);
                return;
            }

            // 获取token
            var tokenResponse = client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,

                ClientId = "client",
                ClientSecret = "secret",
                //Scope = "api1"
            }).Result;

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                return;
            }

            Console.WriteLine(tokenResponse.Json);


            // 用获取到的token访问api
            var client2 = new HttpClient();
            client2.SetBearerToken(tokenResponse.AccessToken);

            var response = client2.GetAsync("http://localhost:5001/api/Values").Result;
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(response.StatusCode);
            }
            else
            {
                var content = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine(JArray.Parse(content));
            }
        }
    }

```

9.测试

此处该有截图

启动IdentityServer
启动ResourcesApi
启动ConsoleClient
用postman测试


## ResourceOwnerPassword授权

1.在Config.cs中添加 TestUser用于测试

```
public static List<TestUser> GetUsers()
{
    return new List<TestUser>
    {
        new TestUser
        {
            SubjectId = "1",
            Username = "tony",
            Password = "123456"
        },
        new TestUser
        {
            SubjectId = "2",
            Username = "thor",
            Password = "456789"
        }
    };
}

```
2.将用户添加到IdentityServer
	修改IdentityServer项目的Startup.cs的ConfigureServices
	
	```
	public void ConfigureServices(IServiceCollection services)
    {
        services.AddIdentityServer()
            .AddDeveloperSigningCredential()
            .AddInMemoryApiResources(Config.GetApiResources())
            .AddInMemoryClients(Config.GetClients())
            .AddInMemoryIdentityResources(Config.GetIdentityResources())
            .AddTestUsers(Config.GetUsers()); //添加测试用户
    }

	```

3.添加一个在Config.cs中添加一个Client
```
new Client
{
    ClientId = "passwordclient",
    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
    ClientSecrets =
    {
        new Secret("secret".Sha256())
    },

    AllowedScopes = { "api1" }
}

```

4.添加一个 ResourceOwnerPasswordClient 项目，在这个客户端去请求受保护的ResourceApi
	修改Program.cs中

```
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello World!");

        var client = new HttpClient();
        var disco = client.GetDiscoveryDocumentAsync("http://localhost:5000").Result;
        if (disco.IsError)
        {
            Console.WriteLine(disco.Error);
            return;
        }

        // 获取token
        var tokenResponse = client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "passwordclient",
            ClientSecret = "secret",

            UserName = "tony",
            Password = "123456",
            //Scope = "api1"
        }).Result;

        if (tokenResponse.IsError)
        {
            Console.WriteLine(tokenResponse.Error);
            return;
        }

        Console.WriteLine(tokenResponse.Json);


        // 用获取到的token访问api
        var client2 = new HttpClient();
        client2.SetBearerToken(tokenResponse.AccessToken);

        var response = client2.GetAsync("http://localhost:5001/api/Values").Result;
        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine(response.StatusCode);
        }
        else
        {
            var content = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine(JArray.Parse(content));
        }
    }
}

```

5.测试

此处该有截图

启动IdentityServer
启动ResourcesApi
启动ResourceOwnerPasswordClient
用postman测试

## Implicit (OpenID Connect简化模式)

	这个模式通过 OpenID Connect 协议向我们的 IdentityServer 添加了对用户认证交互的支持，
	OpenID Connect的协议已经内置在IdentityServer中，
	这个模式要提供UI用于认证交互

1.给IdentityServer添加UI，用于登录，注销，同意授权和显示错误

	这边的UI先用官方的demo，https://github.com/IdentityServer/IdentityServer4.Quickstart.UI/ ，
	把Quickstart,Views,wwwroot文件放到IdentityServer项目目录下,
	修改Startup.cs

	```
	public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                //.AddTestUsers(Config.GetUsers());
				.AddTestUsers(TestUsers.Users); //测试用户在Quickstart文件夹下

            services.AddMvc();
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseIdentityServer();

            app.UseMvcWithDefaultRoute();
        }
    }

	```

2.新建一个MVC客户端，MvcClient,这是MVC应用程序,会自动添加HomeController.cs的相应代码

修改host为：http://localhost:5002

修改Startup.cs

```
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
                options.DefaultScheme = "MvcClientCookies"; //用Cookie在本地登陆
                options.DefaultChallengeScheme = "oidc"; //使用OpenID Connect协议
            })
            .AddCookie("MvcClientCookies")
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "http://localhost:5000"; //信任的IdentityServer地址
                options.RequireHttpsMetadata = false;

                options.ClientId = "mvc";
                options.SaveTokens = true; //在Cookie中保留IdentityServer颁发的令牌
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

```

3.修改HomeController.cs

```
public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [Authorize] //给这个Action添加了授权控制
    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

```

4.修改Privacy.cshtml

```
@using Microsoft.AspNetCore.Authentication

<p>Use this page to detail your site's privacy policy.</p>

<h2>Claims</h2>

<dl>
    @foreach (var claim in User.Claims)
    {
        <dt>@claim.Type</dt>
        <dd>@claim.Value</dd>
    }
</dl>

<h2>Properties</h2>

<dl>
    @foreach (var prop in (await Context.AuthenticateAsync()).Properties.Items)
    {
        <dt>@prop.Key</dt>
        <dd>@prop.Value</dd>
    }
</dl>

```

5.在IdentityServer中的Config.cs中，添加MvcClient这个客户端的配置，修改IdentityResource，增加Scope

```
public static IEnumerable<IdentityResource> GetIdentityResources()
{
    return new IdentityResource[]
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
    };
}

```


```
new Client
{
    ClientId = "mvc",
    ClientName = "MVC Client",
    AllowedGrantTypes = GrantTypes.Implicit,

    // 登录成功回调处理地址，处理回调返回的数据
    RedirectUris = { "http://localhost:5002/signin-oidc" },

    // where to redirect to after logout
    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },

    AllowedScopes = new List<string>
    {
        IdentityServerConstants.StandardScopes.OpenId,
        IdentityServerConstants.StandardScopes.Profile
    }
}

```

可以使用客户端配置上RequireConsent的属性关闭同意授权页面

6.添加注销
使用IdentityServer等身份认证服务，仅清除本地应用程序cookie是不够的。
此外，您还需要向IdentityServer进行往返交互以清除中央单点登录会话。

在HomeController中添加一个注销的控制器

```
public IActionResult Logout()
{
    return SignOut("MvcClientCookies", "oidc");
}

```

在Index.cshtml中增加一个注销链接
```
<a asp-controller="Home" asp-action="Logout">logout</a>

```

7.测试

此处该有截图

启动IdentityServer
启动MvcClient
用postman测试 http://localhost:5000/connect/token


## Hybrid 混合模式

关于混合流程和简化流程的区别，主要是令牌传输方式不同，简化流程中ID Token和Access Token都是通过浏览器传输，
而混合模式中，ID Token通过浏览器传输，ID Token验证成功后再获取Access Token。这是因为访问令牌（AccessToken）比身份令牌（IdentityToken）更敏感。

1.接上面implicit模式，修改IdentityServer的Config.cs，添加一个client

```
new Client
{
    ClientId = "mvc2",
    ClientName = "MVC Client,Hybrid",
    AllowedGrantTypes = GrantTypes.Hybrid,

    ClientSecrets =
    {
        new Secret("secret".Sha256())
    },
    // 登录成功回调处理地址，处理回调返回的数据
    RedirectUris = { "http://localhost:5003/signin-oidc" },

    // where to redirect to after logout
    PostLogoutRedirectUris = { "http://localhost:5003/signout-callback-oidc" },

    AllowedScopes = 
    {
        IdentityServerConstants.StandardScopes.OpenId,
        IdentityServerConstants.StandardScopes.Profile,
        "api1"
    },
    AllowOfflineAccess = true //允许刷新令牌
}

```
2.新建MvcClientHybrid项目，内容与MvcClient内容类似，具体代码查看项目
host改为：http://localhost:5003

3.修改MvcClientHybrid项目的Startup.cs

主要修改内容为：

```
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

```

4.修改HomeController.cs

```
public async Task<IActionResult> CallApi()
{
    var accessToken = await HttpContext.GetTokenAsync("access_token");

    var client = new HttpClient();
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    var content = await client.GetStringAsync("http://localhost:5001/api/Values");

    ViewBag.Json = JArray.Parse(content).ToString();
    return View("json");
}

```
5.在Views/Home下面新建一个json.cshtml

```
<pre>@ViewBag.Json</pre>
<a asp-controller="Home" asp-action="Index">index</a>

```
6.在Index.cshtml和Privacy.cshtml中都加一个链接

```
<a asp-controller="Home" asp-action="CallApi">访问api</a>

```

7.测试

此处该有截图

启动IdentityServer
启动ResourceApi
启动MvcClientHybrid

可以看到，没有登陆的时候点击 访问api 会返回401错误，登陆后可以正常访问，注销后访问会401错误

## 授权码模式

1.新建Javascript客户端，具体看JavaScriptClient项目

host：http://localhost:5004

Javascript客户端主要使用基于 JavaScript 的OIDC组件来处理OpenID Connect协议，
在wwwroot目录下的 oidc-client.js 就是一种基于JavaScript的OIDC组件，https://github.com/IdentityModel/oidc-client-js


2.配置IdentityServer项目的Config.cs,添加一个Client的配置

```
new Client
{
    ClientId = "js",
    ClientName = "JavaScript Client",
    AllowedGrantTypes = GrantTypes.Code,
    RequirePkce = true,
    RequireClientSecret = false,

    RedirectUris =           { "http://localhost:5004/callback.html" },
    PostLogoutRedirectUris = { "http://localhost:5004/index.html" },
    AllowedCorsOrigins =     { "http://localhost:5004" },

    AllowedScopes =
    {
        IdentityServerConstants.StandardScopes.OpenId,
        IdentityServerConstants.StandardScopes.Profile,
        "api1"
    }
}

```
3.在ResourceApi中配置CORS,以便JavaScript客户端跨域调用ResourceApi

在ResourceApi的Startup.cs中

```
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvcCore()
            .AddAuthorization()
            .AddJsonFormatters();

        services.AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = "http://localhost:5000";
                options.RequireHttpsMetadata = false;

                options.Audience = "api1";
            });

        services.AddCors(options =>
        {
            // this defines a CORS policy called "default"
            options.AddPolicy("default", policy =>
            {
                policy.WithOrigins("*")
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
        });
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseCors("default");
        app.UseAuthentication();
        app.UseMvc();
    }
}

```

4.测试

此处该有截图

启动IdentityServer
启动ResourceApi
启动JavascriptClient



