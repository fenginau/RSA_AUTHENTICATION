using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NLog;
using RSAAuth.Models;
using RSAAuth.Utils;
using RSAAuth.Values;

namespace RSAAuth
{
    public class Startup
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            // Load AppSettings to AppSetting class
            Configuration.GetSection("AppSettings").Get<AppSettings>();

            // add JwtBearer authentication
            try
            {
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(RsaUtil.GetRsaParameters(true));
                var secretKey = new RsaSecurityKey(rsa);
                services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = true,
                            ValidateIssuerSigningKey = true,
                            ValidIssuer = Constant.Issuer,
                            ValidAudience = Constant.Audience,
                            IssuerSigningKey = secretKey
                        };
                    });
            }
            catch (Exception e)
            {
                Logger.Error(e);
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }
            app.UseAuthentication(); // use authentication for REST request
            app.UseHttpsRedirection();
            app.UseMvc();

            // Create a new public-private RSA key pair every time
            //RsaUtil.GenerateGlobalRsaKeyPair();
        }
    }
}
