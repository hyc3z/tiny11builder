"""Generate an auditable, per-entry CS2 desktop review; never modifies an image."""
import collections
import hashlib
import html
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'playground/build/tiny11-advanced-removals.json'
OUT = ROOT / 'artifacts/component-analysis'
OUT.mkdir(parents=True, exist_ok=True)
raw = SOURCE.read_bytes()
inventory = json.loads(raw.decode('utf-8-sig'))
SOURCES = {
    'winsxs': 'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder?view=windows-11',
    'fod': 'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11',
    'language': 'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-language-fod?view=windows-11',
    'capability': 'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-capabilities-package-servicing-command-line-options?view=windows-11',
    'userservice': 'https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows',
    'service': 'https://learn.microsoft.com/en-us/windows/win32/services/service-startup',
    'cs2': 'https://store.steampowered.com/app/730/CounterStrike_2/',
    'enablement': 'https://support.microsoft.com/en-gb/servicing/os/windows-11/2023/05/kb5027397-feature-update-to-windows-11-version-23h2-by-using-an-enablement-package',
    'nvidia': 'https://nvidia.custhelp.com/app/answers/detail/a_id/4733',
    'drivers': 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/specifying-driver-load-order',
}
# Group/function/relations here are analysis, not a resolved dependency graph.
def result(group, purpose, deps, impact, recommendation='Keep', reason='', confidence='中', evidence='功能知识与标识推断；未进行此镜像的依赖或启动验证'):
    return dict(Group=group, Purpose=purpose, Dependencies=deps, RemovalImpact=impact,
                Recommendation=recommendation, Reason=reason or '目标游戏环境可能使用，缺少删除后收益证据，建议保留。',
                Confidence=confidence, Evidence=evidence)

APP_REMOVE = {
    'Clipchamp.Clipchamp': ('Clipchamp 视频编辑器', '编辑、模板和导出视频'),
    'Microsoft.549981C3F5F10': ('Cortana 应用', 'Cortana 助手界面'),
    'Microsoft.BingNews': ('资讯应用', '新闻阅读'), 'Microsoft.BingWeather': ('天气应用', '天气查询'),
    'Microsoft.GamingApp': ('Xbox 应用', 'Game Pass 游戏安装管理'),
    'Microsoft.GetHelp': ('获取帮助应用', '微软帮助入口'), 'Microsoft.Getstarted': ('入门提示', '系统使用教程'),
    'Microsoft.MicrosoftOfficeHub': ('Microsoft 365 / Office 入口', 'Office 启动与推广入口'),
    'Microsoft.MicrosoftSolitaireCollection': ('纸牌游戏集合', '微软纸牌游戏'),
    'Microsoft.MicrosoftStickyNotes': ('便笺', '便笺记录和同步'),
    'Microsoft.People': ('人脉应用', '联系人界面'),
    'Microsoft.PowerAutomateDesktop': ('桌面流程自动化', '录制与运行自动化流程'),
    'Microsoft.Todos': ('Microsoft To Do', '待办与账户同步'),
    'Microsoft.WindowsAlarms': ('时钟应用', '闹钟、计时器和专注时段'),
    'Microsoft.WindowsCamera': ('相机应用', '系统自带摄像界面；不是摄像头驱动'),
    'microsoft.windowscommunicationsapps': ('邮件和日历', '邮件、日历与联系人同步界面'),
    'Microsoft.WindowsFeedbackHub': ('反馈中心', '提交反馈与问题录制'),
    'Microsoft.WindowsMaps': ('地图应用', '地图和导航'),
    'Microsoft.WindowsSoundRecorder': ('录音机应用', '自带录音界面；不是音频驱动'),
    'Microsoft.Xbox.TCUI': ('Xbox 游戏交互界面', 'Xbox 账户和游戏相关对话框'),
    'Microsoft.XboxGameOverlay': ('Xbox 游戏覆盖层旧组件', 'Xbox 游戏内界面'),
    'Microsoft.XboxGamingOverlay': ('Xbox Game Bar', 'Win+G、Xbox 录制和覆盖层'),
    'Microsoft.XboxIdentityProvider': ('Xbox 身份提供程序', 'Xbox Live 游戏登录'),
    'Microsoft.XboxSpeechToTextOverlay': ('Xbox 语音文字覆盖层', 'Xbox 辅助交流界面'),
    'Microsoft.YourPhone': ('手机连接', '手机通知、跨设备消息'),
    'Microsoft.ZuneMusic': ('媒体播放器应用', '音乐与媒体播放界面'),
    'Microsoft.ZuneVideo': ('电影和电视应用', '视频商店和播放界面'),
    'MicrosoftCorporationII.QuickAssist': ('快速助手', '微软远程协助'),
    'MicrosoftWindows.Client.WebExperience': ('Windows Web Experience Pack', '小组件等 Web 体验'),
}
APP_KEEP = {
    'Microsoft.DesktopAppInstaller': ('应用安装器 / winget', 'MSIX 安装、winget 管理软件'),
    'Microsoft.SecHealthUI': ('Windows 安全中心界面', '查看防护状态和排查安全设置'),
    'Microsoft.StorePurchaseApp': ('商店购买与许可辅助', 'Store 分发的软件和授权流程'),
    'Microsoft.WindowsStore': ('Microsoft Store', '可能用于 NVIDIA 控制面板等应用分发；非 CS2 直接依赖'),
    'Microsoft.VCLibs.140.00': ('打包应用的 VC++ 框架', 'AppX/MSIX 应用运行；不等于所有桌面 VC++ Redistributable'),
    'Microsoft.Paint': ('画图', '本地截图标注和简单图像处理'),
    'Microsoft.ScreenSketch': ('截图工具', '截图、错误反馈和记录游戏设置'),
    'Microsoft.Windows.Photos': ('照片查看器', '本地截图查看'),
    'Microsoft.WindowsCalculator': ('计算器', '基本桌面工具'),
    'Microsoft.WindowsNotepad': ('记事本', '配置文件与日志编辑'),
    'Microsoft.WindowsTerminal': ('Windows Terminal', 'PowerShell/CMD 等终端宿主；并非 shell 引擎本身'),
}

def app(c):
    name = c['Detail']
    if name in APP_REMOVE:
        title, use = APP_REMOVE[name]
        return result('预装应用 / 精简候选', title + '：' + use, 'AppX 部署及对应应用框架；无已知 CS2/Steam 直接依赖。',
                      '失去' + use + '；以后可能需要从商店重新安装。', 'Remove',
                      '用户仅需 CS2、Steam 和显卡工具；该应用超出范围。主要减少预装内容，不能保证提高 FPS。', '高')
    if name in APP_KEEP:
        title, use = APP_KEEP[name]
        return result('预装应用 / 工具与运行支持', title + '：' + use, use + '；完整包依赖未导出。',
                      '相关界面或应用分发能力丢失；独立工具不启动时通常无持续 CPU 负载。', reason='保留基础安装、排错和桌面工具；不为少量磁盘空间牺牲可维护性。')
    if any(x in name for x in ['ImageExtension', 'VideoExtension', 'WebMediaExtension']):
        return result('媒体 / 编解码扩展', name + '：图片或视频格式扩展。', '使用系统解码器的应用；Steam/网页媒体是否调用取决于实现。',
                      '部分图片或媒体格式无法解码。', reason='按需加载的扩展，删除没有已验证的游戏收益。')
    return result('待核实 / 应用', name, '没有导出 AppX manifest 依赖。', '无法确认所有消费者。', 'Review', '先保留，核实应用清单后再判断。', '低')

SYSTEM_PURPOSE = {
    'LKG': '系统应用的保留/恢复目录；具体内容未导出', 'Shared': '系统应用共享内容目录',
    'AAD.BrokerPlugin': '组织账户与令牌代理', 'AccountsControl': '账户相关系统界面',
    'AsyncTextService': '异步文本输入支持', 'BioEnrollment': 'Windows Hello 生物识别注册界面',
    'creddialoghost': '凭据输入对话框宿主', 'ECApp': '系统内置体验应用，具体功能需核实',
    'LockApp': '锁屏界面', 'MicrosoftEdgeDevToolsClient': '旧 Edge 开发者工具界面',
    'UI.Xaml.CBS': '系统 XAML 界面框架', 'Win32WebViewHost': 'Win32 嵌入式 Web 视图宿主',
    'AddSuggestedFoldersToLibraryDialog': '向库添加建议文件夹的系统对话框',
    'AppRep.ChxApp': '应用信誉检查相关界面', 'AppResolverUX': '打开方式和应用选择界面',
    'AssignedAccessLockApp': '分配访问/自助终端锁定界面', 'CallingShellApp': '系统呼叫相关界面',
    'CapturePicker': '屏幕/窗口捕获选择器', 'CloudExperienceHost': '首次开机与账户设置体验',
    'ContentDeliveryManager': '建议内容、聚焦等体验', 'FileExplorer': '系统文件浏览体验',
    'FilePicker': '系统文件选择器', 'narratorquickstart': '讲述人快速入门',
    'OOBENetworkCaptivePortal': '首次设置中的联网认证门户', 'OOBENetworkConnectionFlow': '首次设置的联网流程',
    'PeopleExperienceHost': '联系人体验宿主', 'PinningConfirmationDialog': '固定应用确认界面',
    'PrintQueueActionCenter': '打印队列界面', 'SecureAssessmentBrowser': '考试/受限评估浏览器',
    'StartMenuExperienceHost': '开始菜单宿主', 'XGpuEjectDialog': '外接 GPU 弹出界面',
    'WindowsAppRuntime.CBS': '系统 Windows App Runtime 支持', 'XboxGameCallableUI': 'Xbox 游戏可调用界面',
    'Client.CBS': 'Windows 客户端系统体验集合', 'Client.Core': 'Windows 客户端核心体验集合',
    'Client.FileExp': '客户端文件浏览体验', 'UndockedDevKit': '系统解耦组件开发/运行支持，边界未导出',
    'NcsiUwpApp': '网络连通性检查相关界面', 'ParentalControls': '家长控制界面',
    'ShellExperienceHost': '桌面 Shell 体验宿主', 'CBSPreview': 'CBS 相关系统预览体验，具体消费者未核实',
}
def system_app(c):
    title = next((v for k, v in sorted(SYSTEM_PURPOSE.items(), key=lambda t: -len(t[0])) if k.lower() in c['Identity'].lower()), '系统应用，精确作用未识别')
    return result('系统应用 / Shell 与共享体验', title, '系统 Shell、账户、部署或其他系统应用可能调用；JSON 无包 manifest/反向引用。',
                  '直接删除 SystemApps 目录可能破坏界面、首次开机或其他调用方。可选功能优先用策略关闭。',
                  'Keep', '这是目录级直接删除，不是受支持的应用卸载。该条目存在不代表常驻运行，CS2 性能收益未经验证。', '中' if '未' not in title else '低')

FEATURE_NAMES = {
    'AppServerClient':'应用服务器客户端支持', 'Client-ProjFS':'投影文件系统（开发工具的虚拟文件树）',
    'DataCenterBridging':'数据中心以太网流量控制', 'DirectoryServices-ADAM-Client':'AD LDS 轻量目录服务',
    'DirectPlay':'旧版 DirectPlay 游戏联网支持，不是 DirectX 11 图形运行时', 'LegacyComponents':'旧版组件父功能',
    'HostGuardian':'受保护虚拟化主机支持', 'HypervisorPlatform':'Windows Hypervisor Platform API',
    'VirtualMachinePlatform':'虚拟机平台（WSL2 等消费者）', 'Microsoft-Windows-Subsystem-Linux':'WSL 子系统',
    'MediaPlayback':'系统媒体播放父功能', 'WindowsMediaPlayer':'传统 Windows Media Player',
    'MicrosoftWindowsPowerShellV2':'旧 PowerShell 2.0 引擎', 'MicrosoftWindowsPowerShellV2Root':'旧 PowerShell 2.0 父功能',
    'MSRDC-Infrastructure':'远程桌面客户端基础组件', 'NetFx3':'.NET Framework 3.5 / 2.0 / 3.0 兼容支持',
    'NetFx4-AdvSrvs':'.NET Framework 4.x 高级服务父功能', 'NetFx4Extended-ASPNET45':'ASP.NET 4.x 支持',
    'Printing-Foundation-Features':'打印基础功能', 'Printing-Foundation-InternetPrinting-Client':'Internet 打印客户端',
    'Printing-Foundation-LPDPrintService':'LPD 打印服务', 'Printing-Foundation-LPRPortMonitor':'LPR 打印端口',
    'Printing-PrintToPDFServices-Features':'Microsoft Print to PDF 虚拟打印机',
    'Printing-XPSServices-Features':'XPS 虚拟打印支持', 'SearchEngine-Client-Package':'Windows 搜索引擎功能',
    'SimpleTCP':'简单 TCP/IP 测试服务', 'SmbDirect':'SMB Direct / RDMA 文件共享',
    'TelnetClient':'Telnet 明文远程终端客户端', 'TFTP':'TFTP 文件传输客户端', 'TIFFIFilter':'TIFF 搜索内容过滤器',
    'Windows-Defender-ApplicationGuard':'基于虚拟化的应用隔离', 'Windows-Defender-Default-Definitions':'Defender 默认病毒定义',
    'Windows-Identity-Foundation':'旧身份联合应用框架', 'WorkFolders-Client':'企业工作文件夹同步',
}
IIS = {'ASP':'传统 ASP','ASPNET':'ASP.NET 旧版本','ASPNET45':'ASP.NET 4.x','CGI':'CGI 程序接口',
       'WebSockets':'WebSocket 支持','WebDAV':'WebDAV 发布','StaticContent':'静态内容','DefaultDocument':'默认文档',
       'DirectoryBrowsing':'目录列表','HttpErrors':'HTTP 错误页','HttpLogging':'HTTP 日志','HttpRedirect':'HTTP 重定向',
       'HttpTracing':'HTTP 跟踪','BasicAuthentication':'基本认证','WindowsAuthentication':'Windows 集成认证',
       'DigestAuthentication':'摘要认证','RequestFiltering':'请求过滤','IPSecurity':'IP 地址限制',
       'ManagementConsole':'管理控制台','FTPServer':'FTP 服务器','FTPSvc':'FTP 服务','FTPExtensibility':'FTP 扩展',
       'ApplicationInit':'应用初始化','ApplicationDevelopment':'应用开发父功能','WebServerRole':'Web 服务器角色',
       'WebServer':'Web 服务器父功能','CommonHttpFeatures':'通用 HTTP 功能','Security':'安全模块父功能',
       'Performance':'性能模块父功能','HealthAndDiagnostics':'诊断父功能','ISAPIExtensions':'ISAPI 扩展','ISAPIFilter':'ISAPI 过滤器',
       'HttpCompressionDynamic':'动态压缩','HttpCompressionStatic':'静态压缩','NetFxExtensibility':'旧 .NET 扩展',
       'NetFxExtensibility45':'.NET 4.x 扩展','RequestMonitor':'请求监视','LoggingLibraries':'日志库','CustomLogging':'自定义日志',
       'ODBCLogging':'ODBC 日志','ServerSideIncludes':'服务器端包含','URLAuthorization':'URL 授权',
       'HostableWebCore':'可嵌入 Web 核心','WebServerManagementTools':'管理工具父功能','ManagementService':'远程管理服务',
       'ManagementScriptingTools':'管理脚本工具','IIS6ManagementCompatibility':'IIS6 管理兼容',
       'Metabase':'旧配置数据库兼容','WMICompatibility':'WMI 管理兼容','LegacyScripts':'旧管理脚本',
       'LegacySnapIn':'旧管理单元','CertProvider':'证书提供程序','ClientCertificateMappingAuthentication':'客户端证书映射认证',
       'IISCertificateMappingAuthentication':'IIS 证书映射认证'}
def feature(c):
    n, state = c['Identity'], c['Detail']
    group, deps = '可选功能 / 桌面与兼容', '具体父子功能关系未导出；应通过 DISM 管理功能，而非删目录。'
    purpose = FEATURE_NAMES.get(n)
    if n.startswith('IIS-'):
        group, purpose, deps = '可选功能 / Web 服务器', 'IIS ' + IIS.get(n[4:], n[4:]), 'IIS 角色及对应认证、管理或运行时父功能；CS2 客户端无需本机 IIS。'
    for prefix, title, relation in [
        ('WAS-', 'Windows 进程激活服务', 'IIS/WCF 服务托管'), ('WCF-', '.NET WCF 通信服务', '.NET 应用和服务托管'),
        ('MSMQ-', '消息队列', 'MSMQ 业务应用'), ('Microsoft-Hyper-V', 'Hyper-V 虚拟化', 'Hyper-V 虚拟机与管理工具'),
        ('Containers', '容器 / 沙盒', 'Windows 容器或沙盒、虚拟化平台'),
        ('Client-Device', '设备锁定', '自助终端部署'), ('Client-Embedded', '嵌入式桌面定制', '自助终端/定制 Shell'),
        ('Client-Keyboard', '键盘过滤', '自助终端按键限制'), ('Client-Unified', '统一写入过滤器', '嵌入式磁盘写入过滤'),
        ('SMB1', '旧 SMB1 协议', '旧 NAS/网络设备；现代 SMB2/3 不属于此功能'),
        ('MultiPoint', 'MultiPoint 多座席支持', '多座席管理')]:
        if n.startswith(prefix): purpose, deps = title + ' / ' + n, relation
    if 'NFS' in n: purpose, deps = 'NFS 客户端或管理功能 / ' + n, 'Unix/NAS 的 NFS 文件共享'
    purpose = purpose or ('可选功能 ' + n + '；具体用途待核实')
    if state != 'Enabled':
        return result(group, purpose, deps, '保持当前未启用状态；删除载荷主要省磁盘，再启用可能需安装源。', 'Keep',
                      f'当前为 {state}，Keep 表示不修改，不会启用它。无常驻功能负载，不因追求 FPS 再做重复移除。', '中')
    if n in {'MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root', 'WorkFolders-Client', 'SmbDirect',
             'Printing-Foundation-InternetPrinting-Client', 'Printing-PrintToPDFServices-Features'}:
        return result(group, purpose, deps, '失去该可选功能；保留载荷以便恢复。', 'Disable', '目标环境不需要，优先禁用，避免父子包直接删除。', '中')
    if n == 'Printing-Foundation-Features':
        return result(group, purpose, deps, '影响所有打印功能及其子功能。', 'Keep', '已单独禁用打印服务与具体功能，保留父功能防止重复操作和依赖冲突。')
    return result(group, purpose, deps, '可能影响现有桌面程序、媒体或管理功能。', 'Keep', '对 CS2/Steam 的间接依赖不能仅靠列表排除；没有针对该项的性能收益证据。')

CAPS = {
 'App.StepsRecorder':('步骤记录器','桌面故障步骤录制','Remove'),
 'Browser.InternetExplorer':('IE 兼容组件','旧网页和嵌入式 Web 控件','Keep'),
 'DirectX.Configuration.Database':('DirectX 配置数据库','图形兼容配置','Keep'),
 'Hello.Face.20134':('Windows Hello 人脸识别','红外相机与人脸登录','Remove'),
 'MathRecognizer':('手写数学识别','手写公式输入','Remove'),
 'Media.WindowsMediaPlayer':('传统媒体播放器','系统媒体播放及旧媒体应用','Keep'),
 'Microsoft.Wallpapers.Extended':('扩展壁纸资源','额外桌面背景','Remove'),
 'Microsoft.Windows.Notepad.System':('传统记事本','文本编辑与故障恢复','Keep'),
 'Microsoft.Windows.PowerShell.ISE':('PowerShell ISE 编辑器','脚本编辑；不等于 PowerShell 引擎','Remove'),
 'Microsoft.Windows.WordPad':('写字板','RTF/文档编辑','Remove'),
 'OneCoreUAP.OneSync':('邮件日历联系人同步支持','OneSync/邮件联系人应用','Remove'),
 'OpenSSH.Client':('SSH 客户端','SSH/SCP/SFTP 管理与开发','Remove'),
 'Print.Management.Console':('打印管理控制台','管理打印机和打印队列','Remove'),
 'Windows.Kernel.LA57':('五级分页相关内核可选载荷','内核内存管理和启动选择','Keep'),
 'WMIC':('旧 WMI 命令行客户端','部分安装器/脚本可能调用；不是 WMI 服务','Keep'),
}
def capability(c):
    n, installed = c['Identity'], c['Detail'] == 'Installed'
    base = n.split('~')[0]
    if base.startswith('Language.'):
        feature_name = base.split('.')[1]
        locale = next((x for x in n.split('~')[1:] if x and not x[0].isdigit()), '未标明')
        names = {'Basic':'基本语言支持','Fonts':'字体','Handwriting':'手写识别','OCR':'光学文字识别','Speech':'语音识别','TextToSpeech':'文本转语音'}
        purpose = f'{locale} / {names.get(feature_name, feature_name)}'
        deps = '同语言基本包、字体及调用此语言服务的应用；具体包依赖未导出。'
        rec = 'Remove' if installed and feature_name in {'Handwriting','Speech','TextToSpeech'} else 'Keep'
        return result('语言 / 输入与识别', purpose, deps, '删除会失去对应语言能力；基本中文和字体删除会影响显示/输入。', rec,
                      '仅保留中文桌面、文字输入和 OCR；该语音/手写能力不在用户范围。' if rec == 'Remove' else
                      ('保留中文基础、字体和截图识别能力。' if installed else '未安装；无需删除，Keep 不会安装它。'), '中')
    if '.Ethernet.' in n or '.Wifi.' in n:
        return result('驱动 / 网络', base + '：内置网卡驱动能力。', '对应 PCI/USB 网卡硬件；CPU 型号不能确定网卡厂商。',
                      '若此驱动匹配实际网卡，删除后安装阶段或系统内会断网。', 'Keep',
                      '目标网卡硬件 ID 未提供，保留联机安装/Steam 所需网络基础；驱动未匹配设备不代表常驻负载。', '高')
    title, deps, rec = CAPS.get(base, (base + '：可选能力，具体消费者待核实', 'FOD 对应功能及其消费者，未提供依赖列表。', 'Review'))
    if not installed: rec = 'Keep'
    return result('可选能力 / 按需功能', title, deps, '移除对应功能；安装器或其他软件若调用它可能失败。', rec,
                  '仅 CS2/Steam 桌面不需要此独立能力，使用 DISM 的 Capability 层移除。' if rec == 'Remove' else
                  ('未安装，不添加任何删除操作。' if not installed else '保留图形、基础工具及可能的间接依赖；无需为小量空间冒险。'), '中')

# Service maps use exact registry identities. No generic driver deletion.
SERVICE_DISABLE = {
 'DiagTrack':('诊断遥测','系统诊断事件上传'), 'MapsBroker':('下载地图管理','离线地图应用'),
 'RetailDemo':('零售演示','门店演示内容'), 'wisvc':('Windows 预览体验','Insider 注册与预览流程'),
 'WMPNetworkSvc':('媒体播放器网络共享','DLNA 媒体共享'), 'workfolderssvc':('工作文件夹同步','企业文件同步'),
 'Fax':('传真','传真设备/应用'), 'Spooler':('打印后台处理','实体打印、PDF 虚拟打印与打印应用'),
 'PrintWorkflowUserSvc':('每用户打印工作流','现代打印界面'),
 'XblAuthManager':('Xbox Live 身份验证','Xbox Live 登录'), 'XblGameSave':('Xbox Live 存档','Xbox 云存档'),
 'XboxNetApiSvc':('Xbox Live 网络','Xbox 联机功能'),
 'BcastDVRUserService':('游戏录制广播','Game DVR/系统游戏录制'),
 'PhoneSvc':('电话集成','设备电话状态'), 'MessagingService':('消息服务','短信与相关应用'),
 'SmsRouter':('短信路由','移动网络短信应用'), 'WalletService':('钱包','钱包支付相关应用'),
 'WpcMonSvc':('家长控制监视','家庭限制'), 'lfsvc':('地理位置','定位应用'),
 'OneSyncSvc':('每用户同步','邮件、日历、联系人同步'),
 'PimIndexMaintenanceSvc':('联系人索引维护','联系人数据库搜索'),
 'UnistoreSvc':('每用户数据存储','邮件、日历、联系人数据'), 'UserDataSvc':('每用户数据访问','邮件、日历、联系人 API'),
 'CDPSvc':('连接设备平台','跨设备体验'), 'CDPUserSvc':('每用户连接设备平台','跨设备体验与附近共享'),
 'TrkWks':('分布式链接跟踪客户端','跨卷/网络文件链接跟踪'),
 'RemoteRegistry':('远程注册表','远程注册表管理'), 'RemoteAccess':('路由与远程访问','将电脑用作路由/VPN 服务端'),
 'WinRM':('Windows 远程管理','PowerShell Remoting / WS-Management'),
 'Wecsvc':('Windows 事件收集器','远程事件订阅'),
 'CscService':('脱机文件','网络共享脱机缓存'),
 'PeerDistSvc':('BranchCache','企业分支缓存'),
 'AssignedAccessManagerSvc':('分配访问管理','自助终端'), 'MsKeyboardFilter':('键盘过滤','自助终端按键控制'),
 'UevAgentService':('用户体验虚拟化','企业设置漫游'),
 'AppVClient':('App-V 客户端','企业应用虚拟化'),
 'MixedRealityOpenXRSvc':('Windows 混合现实 OpenXR','WMR 头显运行环境'),
 'perceptionsimulation':('感知模拟','混合现实开发测试'), 'SharedRealitySvc':('共享现实','混合现实共享体验'),
 'spectrum':('Windows 感知','混合现实空间感知'),
 'SensorDataService':('传感器数据','运动/环境传感器'), 'SensorService':('传感器管理','设备传感器'),
 'SensrSvc':('传感器监视','环境传感器体验'), 'WSearch':('Windows 搜索索引','文件内容索引；非 Steam 游戏搜索'),
}
SERVICE_KEEP = {
 'RpcSs':'RPC 核心', 'RpcEptMapper':'RPC 端点映射', 'DcomLaunch':'DCOM 启动', 'PlugPlay':'即插即用设备管理',
 'Power':'电源策略', 'Schedule':'计划任务', 'EventLog':'事件日志', 'EventSystem':'COM+ 事件系统',
 'ProfSvc':'用户配置文件', 'UserManager':'用户会话管理', 'LSM':'本地会话管理', 'SamSs':'账户数据库',
 'Appinfo':'管理员提升', 'msiserver':'MSI 安装', 'TrustedInstaller':'Windows 组件维护',
 'CryptSvc':'证书、签名和目录验证', 'KeyIso':'密钥隔离', 'sppsvc':'Windows 软件许可',
 'BFE':'基本筛选引擎', 'mpssvc':'Windows 防火墙', 'Dhcp':'DHCP 地址配置', 'Dnscache':'DNS 缓存/名称解析',
 'nsi':'网络状态接口', 'NlaSvc':'网络位置感知', 'netprofm':'网络配置文件', 'Netman':'网络连接管理',
 'Wcmsvc':'连接管理', 'WlanSvc':'WLAN 自动配置', 'iphlpsvc':'IP 辅助与隧道',
 'WinHttpAutoProxySvc':'HTTP 代理发现', 'LanmanWorkstation':'SMB 客户端',
 'Audiosrv':'Windows 音频', 'AudioEndpointBuilder':'音频端点管理', 'MMCSS':'多媒体任务调度',
 'GameInputSvc':'游戏输入', 'hidserv':'HID 人机接口', 'XboxGipSvc':'Xbox 配件管理（可供手柄使用）',
 'TextInputManagementService':'文本输入管理', 'FontCache':'字体缓存', 'Themes':'主题与桌面界面',
 'DispBrokerDesktopSvc':'显示配置代理', 'DisplayEnhancementService':'显示增强', 'GraphicsPerfSvc':'图形性能监视',
 'WarpJITSvc':'Direct3D 软件渲染 JIT', 'DeviceInstall':'设备安装', 'DsmSvc':'设备安装管理',
 'DeviceAssociationService':'设备关联', 'DevQueryBroker':'设备发现查询', 'Winmgmt':'WMI 管理基础',
 'CoreMessagingRegistrar':'核心消息', 'BrokerInfrastructure':'后台基础设施', 'SystemEventsBroker':'系统事件代理',
 'AppXSvc':'AppX 部署', 'ClipSVC':'应用许可', 'InstallService':'商店安装', 'StateRepository':'应用状态数据库',
 'LicenseManager':'应用许可管理', 'AppReadiness':'用户登录应用准备', 'TokenBroker':'账户令牌代理',
 'W32Time':'系统时间同步', 'WinDefend':'Defender 防病毒', 'WdNisSvc':'Defender 网络检查',
 'SecurityHealthService':'安全健康状态', 'wscsvc':'安全中心', 'BITS':'后台传输', 'wuauserv':'Windows 更新',
 'UsoSvc':'更新协调', 'WaaSMedicSvc':'更新修复', 'DoSvc':'传递优化下载',
 'StorSvc':'存储管理', 'defragsvc':'磁盘优化/TRIM 协调', 'VSS':'卷影复制', 'swprv':'软件卷影提供程序',
 'VaultSvc':'凭据保管库', 'NgcSvc':'Hello 密钥支持', 'NgcCtnrSvc':'Hello 密钥容器',
 'seclogon':'辅助登录', 'PcaSvc':'程序兼容性助手', 'DPS':'诊断策略',
 'WerSvc':'Windows 错误报告', 'bthserv':'蓝牙支持', 'BTAGService':'蓝牙音频网关',
 'BthAvctpSvc':'蓝牙音频控制', 'BluetoothUserService':'每用户蓝牙',
}
SERVICE_KEEP.update({
 'AppIDSvc':'应用身份与应用控制支持', 'AppMgmt':'应用管理与策略安装', 'camsvc':'应用能力权限访问管理',
 'CaptureService':'屏幕捕获支持', 'cbdhsvc':'每用户剪贴板', 'CertPropSvc':'智能卡证书传播',
 'COMSysApp':'COM+ 系统应用管理', 'ConsentUxUserSvc':'每用户权限确认界面',
 'CredentialEnrollmentManagerUserSvc':'凭据注册管理', 'DeviceAssociationBrokerSvc':'每用户设备关联代理',
 'DevicePickerUserSvc':'每用户设备选择器', 'DevicesFlowUserSvc':'连接设备界面',
 'DsSvc':'应用间数据共享', 'DusmSvc':'网络流量计量与用量', 'EapHost':'网络 EAP 身份认证',
 'edgeupdate':'Edge/WebView 更新服务', 'edgeupdatem':'Edge/WebView 按需更新服务',
 'EFS':'加密文件系统', 'FrameServer':'相机帧服务', 'FrameServerMonitor':'相机帧服务监视',
 'gpsvc':'组策略客户端', 'IKEEXT':'IPsec/IKE 密钥协商', 'KtmRm':'分布式事务的内核事务协调',
 'LanmanServer':'SMB 文件/打印共享服务端', 'lmhosts':'TCP/IP NetBIOS 辅助',
 'LxpSvc':'语言体验服务', 'MSDTC':'分布式事务协调', 'NaturalAuthentication':'信号聚合与设备身份体验',
 'NcbService':'网络连接代理', 'NetSetupSvc':'网络安装服务', 'NPSMSvc':'正在播放会话管理',
 'PenService':'笔输入支持', 'PerfHost':'性能计数器宿主', 'pla':'性能日志与警报',
 'PolicyAgent':'IPsec 策略代理', 'QWAVE':'音视频网络质量支持', 'RasMan':'远程访问连接管理/VPN',
 'RmSvc':'无线电设备管理', 'SENS':'系统事件通知', 'Sense':'Defender for Endpoint 传感器',
 'SgrmBroker':'系统运行时完整性监视代理', 'ShellHWDetection':'Shell 硬件事件/自动播放',
 'smphost':'存储管理提供程序宿主', 'StiSvc':'Windows 图像采集', 'TimeBrokerSvc':'后台任务时间代理',
 'TroubleshootingSvc':'故障排除支持', 'UdkUserSvc':'每用户 Shell 体验支持',
 'vds':'虚拟磁盘管理', 'WbioSrvc':'生物识别框架', 'WdiServiceHost':'诊断服务宿主',
 'WdiSystemHost':'诊断系统宿主', 'webthreatdefsvc':'Web 威胁防护服务',
 'webthreatdefusersvc':'每用户 Web 威胁防护', 'wercplsupport':'问题报告控制面板支持',
 'WiaRpc':'图像采集设备事件', 'wlidsvc':'Microsoft 账户登录助手',
 'wmiApSrv':'WMI 性能适配器', 'WPDBusEnum':'便携设备枚举',
 'WpnService':'系统推送通知', 'WpnUserService':'每用户推送通知',
})
SERVICE_OPTIONAL = {
 'AarSvc':'对话代理运行时', 'AJRouter':'AllJoyn 设备通信路由', 'ALG':'Internet 连接共享协议插件',
 'autotimesvc':'移动网络自动时间更新', 'AxInstSV':'ActiveX 安装管理', 'BDESVC':'BitLocker 驱动器加密管理',
 'CloudBackupRestoreSvc':'云备份恢复服务', 'cloudidsvc':'Microsoft 云身份服务',
 'dcsvc':'声明配置服务，具体业务边界需核实', 'diagnosticshub.standardcollector.service':'开发性能诊断收集器',
 'diagsvc':'诊断执行', 'DialogBlockingService':'嵌入式对话框过滤', 'DmEnrollmentSvc':'设备管理注册',
 'dmwappushservice':'设备管理 WAP 推送路由', 'dot3svc':'有线 802.1X 自动配置',
 'embeddedmode':'嵌入式/后台应用场景支持', 'EntAppSvc':'企业应用管理',
 'fdPHost':'功能发现提供程序宿主', 'FDResPub':'网络设备发现发布', 'fhsvc':'文件历史记录',
 'HvHost':'Hyper-V 主机接口支持', 'icssvc':'移动热点', 'InventorySvc':'清单与兼容性评估',
 'IpxlatCfgSvc':'IPv4/IPv6 转换配置', 'lltdsvc':'网络拓扑发现映射', 'McpManagementService':'通用打印管理服务',
 'MSiSCSI':'iSCSI 远程存储发起程序', 'NcaSvc':'DirectAccess 网络连接助手',
 'NcdAutoSetup':'网络连接设备自动设置', 'Netlogon':'域登录安全通道', 'NetTcpPortSharing':'WCF TCP 端口共享',
 'p2pimsvc':'对等网络身份', 'p2psvc':'对等网络分组', 'P9RdrService':'Plan 9 文件系统重定向支持',
 'PNRPAutoReg':'对等名称自动注册', 'PNRPsvc':'对等名称解析', 'PushToInstall':'商店远程推送安装',
 'RasAuto':'按需远程访问自动连接', 'RpcLocator':'旧 RPC 名称定位', 'SCardSvr':'智能卡管理',
 'ScDeviceEnum':'智能卡设备枚举', 'SCPolicySvc':'智能卡移除策略', 'SDRSVC':'Windows 备份界面服务',
 'SEMgrSvc':'安全元件管理', 'SessionEnv':'远程桌面会话配置', 'SharedAccess':'Internet 连接共享与网络地址转换',
 'shpamsvc':'共享电脑账户管理', 'SNMPTrap':'SNMP 陷阱接收', 'SSDPSRV':'SSDP 设备发现',
 'ssh-agent':'SSH 私钥代理', 'SstpSvc':'SSTP VPN', 'svsvc':'位置验证，具体调用方需核实',
 'TapiSrv':'电话 API', 'TermService':'远程桌面服务', 'TieringEngineService':'存储分层引擎',
 'tzautoupdate':'自动时区更新', 'UmRdpService':'远程桌面设备/端口重定向', 'upnphost':'UPnP 设备宿主',
 'VacSvc':'空间音频合成服务（不是 Valve Anti-Cheat）', 'wbengine':'块级备份引擎',
 'wcncsvc':'Windows Connect Now / WPS', 'WebClient':'WebDAV 客户端', 'WEPHOSTSVC':'Windows 加密提供程序宿主',
 'WFDSConMgrSvc':'Wi-Fi Direct 服务连接管理', 'wlpasvc':'本地移动配置文件助手/eSIM',
 'WManSvc':'Windows 管理服务，具体消费者需核实', 'WwanSvc':'移动宽带自动配置',
}
def service(c):
    n, d = c['Identity'], c['Detail']
    m = re.search(r'Start=(-?\d+); type=(\d+);', d)
    start, typ = map(int, m.groups()) if m else (-1, 0)
    state = {0:'引导启动',1:'系统启动',2:'自动启动',3:'按需/触发启动',4:'已禁用',-1:'无有效 Start'}.get(start,str(start))
    if typ == 0 or start == -1:
        return result('服务注册表 / 非标准条目', f'{n}：注册表节点，未导出有效服务类型/启动值。',
                      '可能为提供程序配置或其他子系统共享节点，不能当作普通服务。', '删除注册表节点可能损坏 Winsock、性能计数器等基础配置。',
                      'Review','不执行动作；先核实该键的 ServiceDll/ImagePath、Type 和所有引用。','低')
    if typ & 11:
        g, purpose, deps = '驱动 / 内核与硬件', f'{n}：内核/文件系统驱动；{state}。', '硬件 ID、设备堆栈、过滤器、启动配置；此文件未包含关联链。'
        for pattern, group, use, dep in DRIVER_RULES:
            if re.search(pattern, n, re.I): g,purpose,deps=group,f'{n}：{use}；{state}。',dep; break
        return result(g,purpose,deps,'可能造成无法启动、设备失效或过滤链损坏；未匹配硬件的驱动不等于正在占用 CPU。',
                      'Keep','CPU/GPU 型号不足以排除存储、USB、网络及主板依赖；不直接移除驱动服务。','中')
    if n in SERVICE_DISABLE:
        title,deps=SERVICE_DISABLE[n]
        return result('服务 / 目标之外的功能',f'{title}；{state}。',deps+'；精确 DependOnService/反向依赖未导出。',
                      f'{title}对应功能不可用。其他应用调用时可能失败。', 'Keep' if start==4 else 'Disable',
                      '已经禁用，保持现状。' if start==4 else '用户明确只需 CS2/Steam；采用可恢复的禁用，不删除服务键或共享二进制。', '中')
    if n == 'SysMain':
        return result('性能 / 需要实测', '应用预取与内存使用优化；'+state, '应用启动和文件缓存行为。', '可能减少后台 I/O，也可能增加冷启动耗时。',
                      'Review','先保持默认。只有在实体机重复测试证明帧时间改善时再禁用。','中')
    title = SERVICE_KEEP.get(n)
    if title:
        return result('服务 / 游戏与系统基础',title+'；'+state+'。','对应系统/应用消费者；精确服务依赖图未导出。',
                      '可能失去'+title+'，影响游戏、登录、安装、网络或排错。','Keep','保留系统基础和故障诊断链；无足够证据表明禁用会改善 CS2。','中')
    if n.startswith('vmic'):
        return result('服务 / 虚拟机集成',n+'：Hyper-V 来宾集成服务；'+state,'在 Hyper-V 中运行时的宿主/来宾通信。',
                      '虚拟机测试中的关机、时间同步或通信可能受影响。','Keep','实体机通常按需运行；保留镜像虚拟机测试能力，无已证明游戏开销。','中')
    if n in SERVICE_OPTIONAL:
        title=SERVICE_OPTIONAL[n]
        return result('服务 / 可选但需确认依赖', title+'；'+state+'。',
                      title+'的消费者；导出未包含服务依赖及触发器。',
                      '可能失去'+title+'，需先确认设备、网络环境和已有数据不依赖它。',
                      'Keep' if start in {3,4} else 'Review',
                      'CS2 本体无已知直接依赖，但不能排除外设、网络配置或驱动工具调用。当前按需/已禁用则保留状态；无证据证明移除能提高帧率。','中')
    return result('待核实 / 服务',n+'；'+state+'。原始描述：'+d.split(';',2)[-1].strip(),
                  '没有 DependOnService、DependOnGroup、ServiceDll、触发条件及反向消费者。',
                  '用途或依赖边界未充分确认，不把名称猜测当删除依据。','Review','导入后保持未勾选；需要补充离线服务配置才能进一步判断。','低')

DRIVER_RULES = [
 (r'^(ACPI|UEFI|pci|msisadrv|isapnp|Wdf|WUDF|Wudf|amd|intelppm|processor)', '驱动 / 平台与电源','平台总线、处理器或驱动框架','主板 ACPI、CPU、电源管理及设备驱动'),
 (r'(stor|nvme|ahci|raid|disk|partmgr|volmgr|volsnap|volume|spaceport|vdrv|vhd|mountmgr|fltmgr|ntfs|refs|wof|wcifs|fileinfo)', '驱动 / 存储与文件系统','存储/文件系统相关支持','系统盘、控制器、文件系统与过滤驱动'),
 (r'(dxg|display|render|video|nvld|basicdisplay|basicrender|monitor)', '驱动 / 图形','图形显示或渲染支持','DXGI/Direct3D、显示设备、NVIDIA 驱动'),
 (r'(audio|hdaud|portcls|drmk|^ks$|midi)', '驱动 / 音频','音频内核支持','声卡、USB/HDMI 音频、CS2 语音'),
 (r'(usb|ucx|ucm|ufx|urs|hid|kbd|mou|xinput|xbox|i8042|wacom)', '驱动 / USB 与输入','外设总线或输入支持','键鼠、USB、手柄及其他外设'),
 (r'(tcp|ndis|net|wifi|wlan|bth|afd|tdx|nsiproxy|fwpk|wfpl|vwifi|wanarp|^e1|^e2|^rt|^b57)', '驱动 / 网络','网络/无线/蓝牙或过滤支持','网卡、TCP/IP、蓝牙、网络过滤链'),
 (r'(^wd|tpm|trusted|cng|ksec|ci$|sgrm)', '驱动 / 安全与加密','安全、加密或信任支持','代码签名、系统信任、密钥和安全软件'),
 (r'(^vmbus|^vm|^hv|^vid$|^vpci)', '驱动 / 虚拟化','虚拟化平台/来宾支持','Hyper-V、VBS 或虚拟设备，需区分实际消费者'),
]

PAYLOAD_RULES = [
 (r'(common-controls|c\.\.-controls|directui|comdlg32)', 'WinSxS / 公共界面', '公共控件、对话框或 DirectUI 资源', '系统 Shell、Win32 软件和安装器界面'),
 (r'(b\.\.ager-pcat|b\.\.nager-efi)', 'WinSxS / 启动资源', '传统 BIOS/UEFI 启动管理器资源（缩略名推断）', '安装和启动界面'),
 (r'(^system\.|^presentation|^windowsbase|^reachframework|^uiautomation|^microsoft\.visual|^microsoft\.build|^msbuild)', 'WinSxS / 托管框架', '.NET 类库、WPF 或构建支持', '.NET 应用、驱动工具或安装器；需核实程序集引用'),
 (r'(wmi|wbem|rpc|combase|ole32|oleaut|complus|cdosys|transactions|msdtc)', 'WinSxS / 系统通信与管理', 'COM/RPC、管理或事务相关支持', '系统服务、管理工具与应用通信'),
 (r'(mlang|mccs-syncres)', 'WinSxS / 语言与同步资源', '多语言或同步资源（名称推断）', '调用相关资源的系统与应用；精确消费者未导出'),
 (r'(taskkill|tasklist|sctasks|schtasks|netsh|cmd\.exe|powershell|winrs)', 'WinSxS / 管理工具', '命令行管理或任务工具', '维护脚本、故障排查及软件安装器'),
 (r'(servicing|cbs|winsxs|sidebyside|sxs|trustedinstaller|wcp|deployment|dism|foundation|s\.\.ngstack)', 'WinSxS / 维护与部署', '组件服务、并行程序集或部署基础', 'Windows 安装、DISM、更新与组件修复'),
 (r'(direct3d|directx|dxgi|d3d|dxgkrnl|d3dx|directdraw|opengl|vulkan|basicdisplay|basicrender|display|graphics|gpu|dwm|direct2d|dcomp)', 'WinSxS / 图形与显示', '图形、显示、合成或渲染相关载荷', 'CS2 DX11、桌面合成、显卡驱动及可能的软件渲染回退'),
 (r'(audio|sound|mmdev|wasapi|xaudio|xact|xapo|dsound|portcls|hdaud|mmcss)', 'WinSxS / 音频', '音频设备、混音或多媒体音频支持', 'CS2 声音、麦克风、声卡/HDMI/USB 音频'),
 (r'(winsock|tcpip|network|networking|ndis|dhcp|dns|winhttp|wininet|webio|http|ethernet|wlan|wifi|firewall|bfe|wfp)', 'WinSxS / 网络', '网络协议、连接、HTTP 或过滤相关载荷', 'Steam 登录下载、CS2 联机、网卡驱动与证书连接'),
 (r'(kernel|ntdll|hal\b|boot|winload|winresume|acpi|processor|power|pci|pnp|driverframework|wdf)', 'WinSxS / 内核与平台', '内核、启动、平台或驱动框架载荷', '系统启动、9850X3D 平台管理、主板与外设'),
 (r'(storage|storport|stornvme|storahci|disk|ntfs|refs|volume|partition|fltmgr|file-system|filesystem|mountmgr|wof)', 'WinSxS / 存储', '磁盘、文件系统或过滤相关载荷', '系统盘、Steam 游戏文件、驱动安装及镜像读取'),
 (r'(wow64|wow32|syswow)', 'WinSxS / 32 位兼容', '32 位应用兼容支持', '32 位工具、安装器与 Steam 生态辅助程序；64 位游戏不能排除这些消费者'),
 (r'(microsoft\.vc|vcruntime|msvcp|msvcr|ucrt|crt|dotnet|netfx|mscor|clr|gac|fusion|aspnet)', 'WinSxS / 运行库', 'C/C++ 或 .NET 运行库/框架载荷', '软件安装器、驱动面板、系统工具和应用的间接依赖'),
 (r'(shell|explorer|startmenu|taskbar|xaml|comctl|common-controls|gdiplus|gdi|user32|windowmanager|duser)', 'WinSxS / 桌面与 UI', '桌面 Shell 或公共界面支持', '桌面、窗口、文件操作、安装器和显卡控制面板'),
 (r'(input|keyboard|mouse|hid|usb|xinput|gameinput|textservice|ime|inputmethod|textinput)', 'WinSxS / 输入与外设', '输入、文本输入或外设支持', '键鼠、游戏输入、中文输入、USB 设备'),
 (r'(security|crypt|credential|kerberos|schannel|lsa|samlib|logon|auth|tpm|cert|cng|defender|antimalware)', 'WinSxS / 安全与身份', '身份验证、加密、证书或系统安全载荷', 'Windows 登录、TLS、签名验证、平台保护及软件安装'),
 (r'(media|codec|mpeg|wmv|wma|mfplat|mfcapture|video|hevc|h264|av1|wmplayer)', 'WinSxS / 媒体', '媒体框架、编码解码或视频支持', '游戏/Steam 内嵌视频、系统媒体调用和显卡媒体功能'),
 (r'(appx|appmodel|app-model|appreadiness|staterepository|store|appinstaller)', 'WinSxS / 应用部署', '应用模型、打包应用部署或商店支持', '系统应用、安装器、Store 分发的控制面板'),
 (r'(font|nls|globalization|intl|language|text|spell|ocr)', 'WinSxS / 字体与语言', '字体、文字、语言或国际化载荷', '中文显示/输入、游戏与应用文本呈现'),
 (r'(printing|printer|spool|xps|fax)', 'WinSxS / 打印候选关联', '打印、XPS 或传真相关载荷', '打印可选功能、公共图形/文档组件；必须检查 manifest 才能拆分'),
 (r'(hyper-v|hyperv|virtualization|vmbus|vmic|container|wsl)', 'WinSxS / 虚拟化候选关联', '虚拟化、容器或来宾支持载荷', 'Hyper-V、WSL、VBS 或系统共享代码；不能仅凭名称判定只供虚拟机使用'),
 (r'(iis|msmq|nfs|webserver|wcf)', 'WinSxS / 企业可选功能关联', '服务器、消息或业务通信支持', '对应可选功能及其父子包；优先保持功能禁用'),
 (r'(bluetooth|bth)', 'WinSxS / 蓝牙', '蓝牙或相关设备支持', '蓝牙外设、音频与设备配对'),
 (r'(search|indexer)', 'WinSxS / 搜索', '搜索或索引相关载荷', 'Shell 搜索和应用索引；禁用索引服务不等于可直接删除所有搜索文件'),
 (r'(telemetry|diagnostic|feedback|wer|errorreport)', 'WinSxS / 诊断', '诊断、跟踪或错误报告支持', '故障定位、服务/驱动诊断或遥测；系统共享库边界未确认'),
]
def payload(c):
    parts = c['Identity'].split('_')
    identity = re.match(r'^(amd64|x86|wow64|msil|arm64)_(.+)_([0-9a-f]{16})_([0-9.]+)_([^_]+)_([0-9a-f]+)$',c['Identity'],re.I)
    family = identity.group(2) if identity else c['Identity']
    group, purpose, deps, confidence = 'WinSxS / 未识别家族', '内部组件家族 '+family+'；名称不足以确定精确用途。', '未知；需组件 manifest、所属包、硬链接和反向依赖。', '低'
    if c['Identity'] in {'Catalogs','FileMaps','Fusion','InstallTemp','Manifests','SettingsManifests','Temp'}:
        group,purpose,deps,confidence='WinSxS / 元数据','组件存储元数据或事务目录 '+c['Identity'],'CBS、安装、维护与并行程序集解析','高'
    else:
        for pattern,g,p,d in PAYLOAD_RULES:
            if re.search(pattern,family,re.I): group,purpose,deps,confidence=g,p+'（名称推断：'+family+'）',d,'中'; break
        if '.inf' in family and group == 'WinSxS / 未识别家族':
            group,purpose,deps,confidence='WinSxS / 驱动安装与资源',family+'：驱动 INF 相关资源（名称推断）','对应硬件安装、驱动包与本地化资源；未提供硬件 ID','中'
    arch = identity.group(1) if identity else 'metadata'
    if identity:
        purpose += f' 架构 {arch}；版本 {identity.group(4)}；语言 {identity.group(5)}。'
        if '.resources' in family: purpose += ' 这是本地化资源载荷；语言或资源存在不代表正在执行。'
    suffix = ' x86/wow64 是兼容载荷，不因 CPU 为 64 位就判为多余。' if arch in {'x86','wow64'} else ''
    return result(group,purpose,deps+'；不是此组件的完整依赖列表。',
                  '此操作直接删除 WinSxS 目录，绕过组件服务；可能损坏启动、修复或应用。文件硬链接关系未提供，目录大小也不等于可回收空间。'+suffix,
                  'Keep' if confidence!='低' else 'Review',
                  '针对 CS2 性能，不直接删除该载荷。若确实不需要所属功能，应在 Feature/Capability 层操作并验证。',
                  confidence,'组件身份名称/架构推断；没有读取 manifest，没有逐项运行验证。'+SOURCES['winsxs'])

def package(c):
    n = c['Identity'].split('~')[0]
    purpose = n+'：Windows 组件服务包。'
    if n.startswith('Package_for_'):
        purpose = {'Package_for_KB5027397':'Windows 11 23H2 启用包（基础镜像仍可能显示 22621）',
                   'Package_for_RollupFix':'Windows 累积更新包','Package_for_DotNetRollup_481':'.NET 累积更新包'}.get(n,
                   '服务堆栈更新包' if 'ServicingStack' in n else 'Windows 更新包')
    else:
        for pattern, _, title, _ in PAYLOAD_RULES:
            if re.search(pattern,n,re.I): purpose=n+'：'+title+'对应包（名称推断）'; break
    return result('CBS 包 / 维护与 FOD 容器',purpose,'包身份、状态已知；永久性、父包、取代链、能力映射未完整导出。',
                  '直接删包可能与 Capability/Feature 操作重复，或破坏更新和父子包关系。',
                  'Keep','不在 Package 层重复移除。可选能力由对应 Capability 项处理；这里 Keep 不代表阻止能力移除时自动处理其包。','中')

handlers={'ProvisionedApp':app,'SystemApp':system_app,'Feature':feature,'Capability':capability,'Service':service,'ComponentPayload':payload,'Package':package}
rows=[]
for c in inventory['Components']:
    a=handlers[c['Kind']](c)
    a.update(Kind=c['Kind'],Identity=c['Identity'],OriginalDetail=c['Detail'],Protected=c['Protected'])
    a['DependencyStatus']='仅说明功能关联，未解析完整依赖图'
    a['CanOmit'] = {'Remove':'可以，接受上述功能损失后移除。','Disable':'建议禁用而非删除载荷/服务键。',
                   'Keep':'不建议直接移除；Keep 表示保持当前状态，不负责启用。',
                   'Review':'证据不足，不自动移除，需进一步核实。'}[a['Recommendation']]
    a['PerformanceExpectation']='没有逐项 CS2 基准数据；删除大小、后台进程数量不能直接换算 FPS。'
    rows.append(a)

counts=collections.Counter(x['Recommendation'] for x in rows)
groups=collections.Counter(x['Group'] for x in rows)
report=dict(SchemaVersion=1,ReportType='Tiny11Builder.RemovalAnalysis',Image=inventory['Image'],
 Profile='AMD 9850X3D + NVIDIA RTX 5000 系列，CS2 DX11 / Steam 专用简体中文桌面；不需要 Xbox/Game Pass、打印、办公同步与虚拟机工作负载。',
 SourceInventorySha256=hashlib.sha256(raw).hexdigest(),
 Limitations=['本文件是基于清单的逐项功能/风险分流，不是经过实测的完整依赖审计。',
 '依赖字段是已知/推断的功能关联；清单未包含 manifest、DependOnService、硬件 ID、文件内容和运行轨迹。',
 '每个原始条目有且仅有一条建议。未知项标记 Review，导入后不选择删除。',
 'Keep 对未安装/已禁用项表示保持状态；不安装/启用。',
 '建议未测量 FPS、内存、延迟或回收空间。精简预装应用主要改变功能与体积。',
 '镜像基础版本 22621.4169；清单含 KB5027397 启用包，不能仅凭基础 WIM 版本断言最终桌面版本。',
 'NVIDIA/AMD 第三方驱动本体及网卡硬件 ID 未在清单中；安装后仍需验证驱动与游戏。'],
 Sources=SOURCES,RecommendationCounts=dict(counts),Components=rows)
(OUT/'goat-os-cs2-analysis.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
labels={'Keep':'保留现状','Remove':'删除','Disable':'禁用','Review':'待核实（不执行）'}
summary=['# goat-os / CS2 专用组件分析','',report['Profile'],'',
 f"输入：{inventory['Image']['Name']} / {inventory['Image']['Version']} / {inventory['Image']['Architecture']}，{len(rows):,} 项。",'',
 '## 阅读边界','']+['- '+x for x in report['Limitations']]+['','## 建议数量','',
 '| 建议 | 数量 |','|---|---:|']+[f'| {labels[k]} | {v:,} |' for k,v in counts.items()]+['',
 '## 按功能分组','', '| 分组 | 数量 |','|---|---:|']+[f'| {k} | {v:,} |' for k,v in sorted(groups.items())]+['',
 '## 实际选择的移除/禁用项','', '| 类型 | 组件 | 建议 | 功能损失 |','|---|---|---|---|']+[
 f"| {r['Kind']} | `{r['Identity']}` | {labels[r['Recommendation']]} | {r['RemovalImpact']} |" for r in rows if r['Recommendation'] in {'Remove','Disable'}]+['',
 '## 使用','',
 '打开 goat-os-cs2-report.html 可按组、类型、建议或名称搜索全部条目。每项展开显示作用、关联依赖、影响、依据和置信度。',
 '软件中选择 Custom，加载同一镜像版本/版本索引，List all components → Import analysis (.json)。',
 '导入 analysis.json 后会立即勾选 Remove/Disable 建议，并叠加到现有计划；Group、Core 和手动选择保留。Keep/Review 不会撤销已有选择，也不能阻止组或 Core 删除该项。',
 '仅 Remove/Disable 会被选中；Keep/Review 不执行。依赖不是由导入器求解的。',
 '本次建议针对该旧镜像；更换新版 Windows 后须重新导出分析，不能只修改 JSON 中版本号。',
 '建议先验证安装、Steam 登录/下载、NVIDIA 驱动控制面板、CS2 DX11、音频/麦克风、网络和鼠标键盘；性能在实体机重复测量。','',
 '## 参考','']+['- '+k+': '+v for k,v in SOURCES.items()]
(OUT/'README.zh-CN.md').write_text('\n'.join(summary),encoding='utf-8')

data=json.dumps(rows,ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
page='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>goat-os · CS2 组件分析</title>
<style>body{font:15px/1.65 system-ui,sans-serif;background:#10151c;color:#e4eaf2;margin:0}main{max-width:1250px;margin:auto;padding:30px}h1{font-size:30px}p{color:#bfcbd9}.panel,article{background:#192330;border:1px solid #304257;border-radius:12px;padding:18px;margin:12px 0}nav{position:sticky;top:0;background:#10151cf5;padding:12px 0;display:flex;flex-wrap:wrap;gap:8px}input,select,button{font:inherit;padding:9px;border-radius:7px;background:#233347;color:white;border:1px solid #49617a}input{flex:1;min-width:230px}summary{cursor:pointer;overflow-wrap:anywhere}b{color:#8fd9c5}dl{display:grid;grid-template-columns:110px 1fr;gap:8px}dt{color:#9bb0c9}dd{margin:0;overflow-wrap:anywhere}small{color:#adc1d8}a{color:#9acfff}.Remove{color:#f6af7c}.Disable{color:#edcf74}.Review{color:#bba8ff}.Keep{color:#8fd9c5}</style>
<main><h1>goat-os · CS2 专用组件分析</h1><p>9850X3D / RTX 5000 系列 / Steam / DX11 / 简体中文</p>
<section class="panel"><b>15,308 个原始条目，逐项对应；没有执行任何删除。</b><p>依赖说明为功能关联，不是完整依赖图。WinSxS 按家族和身份名称分组；未知项明确标为待核实。Keep 对已禁用/未安装项表示保持原状。目标镜像 10.0.22621.4169 / Professional / x64 / Index 4；存在 KB5027397 启用包。</p><p id="totals"></p><a href="goat-os-cs2-analysis.json" download>下载可导入 JSON</a> · <a href="README.zh-CN.md">阅读分组与行动摘要</a></section>
<nav><input id="q" placeholder="搜索组件、用途、依赖或关键词"><select id="group"><option value="">全部功能分组</option></select><select id="kind"><option value="">全部类型</option></select><select id="rec"><option value="">全部建议</option><option>Remove</option><option>Disable</option><option>Keep</option><option>Review</option></select></nav>
<p id="status"></p><button id="prev">上一页</button> <button id="next">下一页</button><div id="list"></div>
<script id="data" type="application/json">__DATA__</script><script>
const rows=JSON.parse(document.getElementById('data').textContent),labels={Keep:'保留现状',Remove:'删除',Disable:'禁用',Review:'待核实'},$=id=>document.getElementById(id);let page=0,filtered=[];
for(const [id,key] of [['group','Group'],['kind','Kind']])for(const name of [...new Set(rows.map(r=>r[key]))].sort()){const o=document.createElement('option');o.textContent=name;$(id).append(o)}
const counts={};rows.forEach(r=>counts[r.Recommendation]=(counts[r.Recommendation]||0)+1);$('totals').textContent=Object.entries(counts).map(([k,v])=>labels[k]+' '+v.toLocaleString()).join(' · ');
function draw(){const query=$('q').value.toLowerCase();filtered=rows.filter(r=>(!$('group').value||r.Group===$('group').value)&&(!$('kind').value||r.Kind===$('kind').value)&&(!$('rec').value||r.Recommendation===$('rec').value)&&(!query||[r.Identity,r.Purpose,r.Dependencies,r.Group,r.Reason].join(' ').toLowerCase().includes(query)));const pages=Math.max(1,Math.ceil(filtered.length/60));page=Math.min(page,pages-1);$('status').textContent=`匹配 ${filtered.length.toLocaleString()} 项 · 第 ${page+1}/${pages} 页（每页 60 项）`;$('prev').disabled=page===0;$('next').disabled=page+1>=pages;$('list').replaceChildren();for(const r of filtered.slice(page*60,page*60+60)){const a=document.createElement('article'),d=document.createElement('details'),s=document.createElement('summary'),tag=document.createElement('b');tag.className=r.Recommendation;tag.textContent=labels[r.Recommendation]+' · ';s.append(tag,document.createTextNode(r.Identity));const small=document.createElement('small');small.textContent=r.Group+' · '+r.Kind+' · 置信度：'+r.Confidence;const dl=document.createElement('dl');for(const [key,title] of [['OriginalDetail','原始状态'],['Purpose','作用'],['CanOmit','能否不保留'],['Dependencies','依赖/关联'],['DependencyStatus','依赖核实状态'],['RemovalImpact','删除影响'],['Reason','推荐理由'],['PerformanceExpectation','性能预期'],['Evidence','证据']]){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=title;dd.textContent=r[key];dl.append(dt,dd)}d.append(s,small,dl);a.append(d);$('list').append(a)}}
for(const id of ['q','group','kind','rec'])$(id).addEventListener('input',()=>{page=0;draw()});$('prev').onclick=()=>{page--;draw()};$('next').onclick=()=>{page++;draw()};draw();</script></main></html>'''
(OUT/'goat-os-cs2-report.html').write_text(page.replace('__DATA__',data),encoding='utf-8')
print(json.dumps({'total':len(rows),'recommendations':counts,'groups':len(groups),'bytes':(OUT/'goat-os-cs2-analysis.json').stat().st_size},ensure_ascii=False))
