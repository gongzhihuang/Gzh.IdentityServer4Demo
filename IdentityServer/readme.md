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