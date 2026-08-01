// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services;

partial interface IPlatformService
{
    private static (byte[] key, byte[] iv) GetMachineSecretKey(string? value)
    {
        value ??= string.Empty;
        var result = AESUtils.GetParameters(value);
        return result;
    }

    protected static Lazy<(byte[] key, byte[] iv)> GetMachineSecretKey(Func<string?> action) => new(() =>
    {
        string? value = null;
        try
        {
            value = action();
        }
        catch (Exception e)
        {
            Log.Warn(TAG, e, "GetMachineSecretKey fail.");
        }
        if (string.IsNullOrWhiteSpace(value))
        {
            value = Environment.MachineName;
        }
        return GetMachineSecretKey(value);
    });

    /// <summary>
    /// 异步实现的机器密钥获取，避免 SecureStorage IO 在 UI 线程上同步阻塞。
    /// </summary>
    private static async Task<(byte[] key, byte[] iv)> GetMachineSecretKeyBySecureStorageAsync()
    {
        if (!CommonEssentials.IsSupported) throw new PlatformNotSupportedException();
        const string KEY_MACHINE_SECRET = "KEY_MACHINE_SECRET_2105";
        var guidStr = await ISecureStorage.Instance.GetAsync(KEY_MACHINE_SECRET);
        if (Guid.TryParse(guidStr, out var guid))
        {
            return AESUtils.GetParameters(guid.ToByteArray());
        }
        guid = Guid.NewGuid();
        guidStr = guid.ToString();
        await ISecureStorage.Instance.SetAsync(KEY_MACHINE_SECRET, guidStr);
        return AESUtils.GetParameters(guid.ToByteArray());
    }

    /// <summary>
    /// 机器密钥的异步单例。第一次 await 时后台执行 IO，
    /// Value 完成后再访问 MachineSecretKey 属性就不会阻塞。
    /// </summary>
    private static readonly Lazy<Task<(byte[] key, byte[] iv)>> mMachineSecretKeyBySecureStorageAsync =
        new(() => Task.Run(GetMachineSecretKeyBySecureStorageAsync), LazyThreadSafetyMode.ExecutionAndPublication);

    [ThreadStatic]
    private static (byte[] key, byte[] iv) mCachedMachineSecretKeyTuple;
    [ThreadStatic]
    private static bool mCachedMachineSecretKeyInitialized;

    /// <summary>
    /// 同步访问机器密钥：优先使用已完成的后台结果；如果还没做完就 RunSync。
    /// 在启动预热（ConfigureAwaitOptions.ForceYielding 已调度后台执行）后，
    /// 正常首次使用都会命中已完成的 Task，不会再阻塞。
    /// </summary>
    (byte[] key, byte[] iv) MachineSecretKey
    {
        get
        {
            if (mCachedMachineSecretKeyInitialized) return mCachedMachineSecretKeyTuple;
            var task = mMachineSecretKeyBySecureStorageAsync.Value;
            try
            {
                if (task.Status == TaskStatus.RanToCompletion)
                {
                    mCachedMachineSecretKeyTuple = task.Result;
                    mCachedMachineSecretKeyInitialized = true;
                    return mCachedMachineSecretKeyTuple;
                }
                mCachedMachineSecretKeyTuple = task.GetAwaiter().GetResult();
                mCachedMachineSecretKeyInitialized = true;
                return mCachedMachineSecretKeyTuple;
            }
            catch (AggregateException e)
            {
                if (e.InnerException is PlatformNotSupportedException)
                {
                    // 回退到 Environment.MachineName 派生的同步密钥，避免启动因 SecureStorage 失败而终止
                    mCachedMachineSecretKeyTuple = GetMachineSecretKey(Environment.MachineName);
                    mCachedMachineSecretKeyInitialized = true;
                    return mCachedMachineSecretKeyTuple;
                }
                throw;
            }
        }
    }

    /// <summary>
    /// 异步获取机器密钥。用于启动流程预热，避免同步属性访问阻塞 UI。
    /// </summary>
    protected async Task<(byte[] key, byte[] iv)> GetMachineSecretKeyAsync()
    {
        if (mCachedMachineSecretKeyInitialized) return mCachedMachineSecretKeyTuple;
        var result = await mMachineSecretKeyBySecureStorageAsync.Value;
        mCachedMachineSecretKeyTuple = result;
        mCachedMachineSecretKeyInitialized = true;
        return result;
    }
}