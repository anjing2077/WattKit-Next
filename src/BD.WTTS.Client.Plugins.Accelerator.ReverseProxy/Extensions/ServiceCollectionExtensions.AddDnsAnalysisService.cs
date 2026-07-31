// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static partial class ServiceCollectionExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IServiceCollection AddDnsAnalysisService(this IServiceCollection services)
    {
        services.AddSingleton<DnsDohAnalysisService>();
        services.AddSingleton<DnsAnalysisServiceImpl>();

        // DNS 污染防护 Phase 2/5（方案 A：0 新依赖，装饰器模式）
        // 注册顺序：L3.3 锚点 → L3 验证器 → L2 并行解析器
        // 三个均为 Singleton，初始化极轻量（L3.3 为懒加载，1.2KB 内置黑洞列表）
        // 绝不阻塞启动；真正的工作是在 YARP 第一次转发 DNS 时才触发。
        services.AddSingleton<DnsFingerprintAnchor>();
        services.AddSingleton<DnsResultVerifier>();
        services.AddSingleton<DnsParallelResolver>();

        return services;
    }
}