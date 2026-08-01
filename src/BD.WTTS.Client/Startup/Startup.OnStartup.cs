// ReSharper disable once CheckNamespace
namespace BD.WTTS;

partial class Startup // OnStartup
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    static void InitVisualStudioAppCenterSDK()
    {
        VisualStudioAppCenterSDK.Init();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ShowSettingsModifiedRestartThisSoft()
    {
        if (Ioc.Get_Nullable<IToastIntercept>() is StartupToastIntercept intercept
            && !intercept.IsStartuped)
        {
            return;
        }
        Toast.Show(ToastIcon.Info, Strings.SettingsModifiedRestartThisSoft);
    }

    public virtual void InitSettingSubscribe()
    {
        var a = IApplication.Instance;

        UISettings.Theme.Subscribe(x => a.Theme = x);
        UISettings.Language.Subscribe(ResourceService.ChangeLanguage);

        GeneralSettings.GPU.Subscribe(x =>
        {
            //if (x.HasValue) // null 为默认值时不提示
            ShowSettingsModifiedRestartThisSoft();
        });
        GeneralSettings.PluginSafeMode.Subscribe(x =>
        {
            //if (x.HasValue) // null 为默认值时不提示
            ShowSettingsModifiedRestartThisSoft();
        });

#if (WINDOWS || MACCATALYST || MACOS || LINUX) && !(IOS || ANDROID)
        // 启动优化: SteamProgramPath 检测移到后台, 避免阻塞 UI 线程 (原同步调用 Ioc.Get<ISteamService>())
        if (string.IsNullOrWhiteSpace(SteamSettings.SteamProgramPath.Value))
        {
            Task2.InBackground(() =>
            {
                try
                {
                    var steamPath = Ioc.Get<ISteamService>().SteamProgramPath;
                    if (!string.IsNullOrWhiteSpace(steamPath))
                        SteamSettings.SteamProgramPath.Default = steamPath;
                }
                catch (Exception ex)
                {
                    GlobalExceptionHandler.Handler(ex, "StartupOpt.SteamProgramPath");
                }
            });
        }
#endif
    }

    public virtual void OnStartup()
    {
        StartupToastIntercept.OnStartuped();

#if STARTUP_WATCH_TRACE || DEBUG
        WatchTrace.Start();
#endif
        InitVisualStudioAppCenterSDK();
#if STARTUP_WATCH_TRACE || DEBUG
        WatchTrace.Record("VisualStudioAppCenter");
#endif

        if (IsMainProcess)
        {
            Task2.InBackground(async () =>
            {
                await ActiveUserRecordAsync(ActiveUserAnonymousStatisticType.OnStartup);
            });
            if (GeneralSettings.AutoCheckAppUpdate.Value)
            {
                Task2.InBackground(async () =>
                {
                    await IAppUpdateService.Instance
                        .CheckUpdateAsync(showIsExistUpdateFalse: false);
                });
            }
        }
#if DEBUG
        DebugConsole.WriteInfo();
#endif

#if STARTUP_WATCH_TRACE || DEBUG
        WatchTrace.Stop();
#endif
    }

    protected abstract ActiveUserRecordDTO GetActiveUserRecord();

    [MethodImpl(MethodImplOptions.NoInlining)]
    async Task ActiveUserRecordAsync(ActiveUserAnonymousStatisticType type)
    {
        if (!IsMainProcess)
            return;

        try
        {
            var userService = UserService.Current;
            var isAuthenticated = userService.IsAuthenticated;
            var csc = IMicroServiceClient.Instance;
            if (isAuthenticated)
            {
                // 刷新用户信息
                var rspRUserInfo = await csc.Manage.RefreshUserInfo();
                if (rspRUserInfo.IsSuccess && rspRUserInfo.Content != null)
                {
                    await userService.SaveUserAsync(rspRUserInfo.Content);
                }
            }

            var request = GetActiveUserRecord();
            request.Type = type;
            request.IsAuthenticated = isAuthenticated;
            await csc.ActiveUser.Record(request);
        }
        catch (Exception ex)
        {
            GlobalExceptionHandler.Handler(ex, nameof(ActiveUserRecordAsync));
        }
    }
}