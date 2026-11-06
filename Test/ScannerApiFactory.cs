using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Server.Options;

namespace Scanner.Tests;

internal sealed class ScannerApiFactory : WebApplicationFactory<Program>
{
    private readonly Dictionary<string, string?> _configuration;
    private readonly bool _useLoopbackRemoteAddress;

    public ScannerApiFactory(
        Dictionary<string, string?>? configuration = null,
        bool useLoopbackRemoteAddress = true)
    {
        _useLoopbackRemoteAddress = useLoopbackRemoteAddress;
        _configuration = new Dictionary<string, string?>
        {
            ["RateLimit:PermitLimit"] = "1000",
            ["RateLimit:WindowSeconds"] = "1"
        };

        if (configuration is not null)
        {
            foreach (var item in configuration)
            {
                _configuration[item.Key] = item.Value;
            }
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(_configuration);
        });

        builder.ConfigureServices(services =>
        {
            var options = new ConfigurationBuilder()
                .AddInMemoryCollection(_configuration)
                .Build()
                .GetSection(ScannerOptions.SectionName)
                .Get<ScannerOptions>() ?? new ScannerOptions();

            services.RemoveAll<ScannerOptions>();
            services.AddSingleton(options);

            IPAddress remoteAddress = _useLoopbackRemoteAddress
                ? IPAddress.Loopback
                : IPAddress.Parse("203.0.113.1");
            services.AddSingleton<IStartupFilter>(new RemoteAddressStartupFilter(remoteAddress));
        });
    }

    private sealed class RemoteAddressStartupFilter(IPAddress remoteAddress) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = remoteAddress;
                await nextMiddleware();
            });

            next(app);
        };
    }
}
