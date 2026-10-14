"""Target-specific analysis of the user-supplied inventory/template. No image edits."""
import collections
import copy
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
source = ROOT / 'playground/build/tiny11-advanced-removals.json'
template_path = ROOT / 'playground/build/tiny11-advanced-removals-ai-56c8b79f/analysis-template.json'
baseline_path = ROOT / 'artifacts/component-analysis/goat-os-cs2-analysis.json'
out = ROOT / 'artifacts/cs2-competition-extreme'
out.mkdir(parents=True, exist_ok=True)
inventory = json.loads(source.read_text(encoding='utf-8-sig'))
template = json.loads(template_path.read_text(encoding='utf-8-sig'))
baseline = json.loads(baseline_path.read_text(encoding='utf-8-sig'))
key = lambda r: (r['Kind'], r['Identity'])
original = {key(r):r for r in inventory['Components']}
prior = {key(r):r for r in baseline['Components']}
assert len(original) == len(inventory['Components']) == len(template['Components'])
assert set(original) == {key(r) for r in template['Components']} == set(prior)
for field in ['Index','Architecture','Version','Edition','Installation']:
    assert template['Image'][field] == inventory['Image'][field] == baseline['Image'][field]

extra_services = {
    'AJRouter':('AllJoyn 设备通信路由','不提供 AllJoyn 智能设备通信'),
    'AarSvc':('对话代理运行时','系统语音助手不可用；不等于游戏语音'),
    'autotimesvc':('移动网络时间更新','不通过蜂窝网络更新时间；保留 W32Time'),
    'AxInstSV':('ActiveX 安装服务','网页 ActiveX 控件安装不可用'),
    'CloudBackupRestoreSvc':('云备份恢复','不提供云端设置恢复'),
    'DialogBlockingService':('嵌入式对话框过滤','不提供自助终端对话框拦截'),
    'DmEnrollmentSvc':('设备管理注册','不进行 MDM 企业注册'),
    'dmwappushservice':('设备管理推送','不处理 MDM WAP 推送'),
    'EntAppSvc':('企业应用管理','不支持企业应用管理流程'),
    'fdPHost':('网络功能发现宿主','自动发现共享设备的功能失效；不禁用 IP 联机'),
    'FDResPub':('网络功能发现发布','本机不向网络发现发布共享资源'),
    'fhsvc':('文件历史记录','不提供文件历史备份'),
    'icssvc':('移动热点','不能将比赛电脑用作移动热点'),
    'lltdsvc':('网络拓扑发现映射','网络拓扑图发现不可用'),
    'McpManagementService':('通用打印管理','不提供通用打印管理'),
    'NcaSvc':('DirectAccess 连接助手','不提供企业 DirectAccess 连接辅助'),
    'NetTcpPortSharing':('WCF TCP 端口共享','依赖此共享机制的 WCF 服务不可用'),
    'p2pimsvc':('Windows 对等网络身份','Windows 对等分组身份不可用；并非 Steam 网络实现'),
    'p2psvc':('Windows 对等网络分组','旧 Windows 对等分组不可用'),
    'PNRPAutoReg':('对等名称自动注册','不进行 Windows PNRP 名称注册'),
    'PNRPsvc':('对等名称解析','不提供 Windows PNRP 名称解析；保留 DNS'),
    'PushToInstall':('远程推送应用安装','不接受商店远程推送安装'),
    'RpcLocator':('旧 RPC 名称定位','旧 RPC 名称定位不可用；保留 RpcSs/RpcEptMapper'),
    'SCardSvr':('智能卡管理','不支持智能卡登录/应用'),
    'ScDeviceEnum':('智能卡设备枚举','不枚举智能卡设备'),
    'SCPolicySvc':('智能卡移除策略','不执行拔出智能卡后的会话策略'),
    'CertPropSvc':('智能卡证书传播','不将智能卡证书传播到用户证书库；保留 CryptSvc'),
    'SDRSVC':('Windows 备份界面服务','不提供该系统备份流程'),
    'SEMgrSvc':('安全元件管理','安全元件相关支付/应用体验不可用'),
    'SessionEnv':('远程桌面会话配置','不支持 RDP 会话配置'),
    'TermService':('远程桌面服务','不接受 RDP 远程桌面连接'),
    'UmRdpService':('远程桌面重定向','不支持 RDP 外设/端口重定向'),
    'shpamsvc':('共享电脑账户管理','不提供共享电脑自动账户维护'),
    'SNMPTrap':('SNMP 陷阱接收','不接受 SNMP 管理消息'),
    'SSDPSRV':('SSDP 发现','UPnP/媒体设备自动发现不可用'),
    'upnphost':('UPnP 设备宿主','本机不托管 UPnP 设备'),
    'ssh-agent':('SSH 密钥代理','SSH 私钥代理不可用；不影响 Steam 凭据'),
    'StiSvc':('Windows 图像采集','扫描仪和相机图像采集应用不可用'),
    'WiaRpc':('图像采集设备事件','扫描/图像采集事件不可用'),
    'FrameServer':('相机帧服务','依赖该服务的摄像应用不可用'),
    'FrameServerMonitor':('相机帧服务监视','不监视相机帧服务'),
    'WebClient':('WebDAV 客户端','不能使用 WebDAV 网络文件路径；不禁用 HTTP 网络库'),
    'wbengine':('块级备份引擎','系统映像备份不可用'),
    'WwanSvc':('移动宽带','不支持蜂窝调制解调器；比赛使用有线/普通网卡'),
    'wlpasvc':('eSIM 配置助手','不管理 eSIM 配置'),
    'WMPNetworkSvc':('媒体网络共享','不提供媒体库的网络共享'),
}
# Single root per optional-feature family; avoid independently deleting its children.
feature_remove = {
    'IIS-WebServerRole':'本机 IIS Web/FTP 服务器父角色',
    'WAS-WindowsActivationService':'IIS/WCF 进程激活父功能',
    'MSMQ-Container':'企业消息队列父功能',
    'ClientForNFS-Infrastructure':'NFS 客户端父功能',
    'MultiPoint-Connector':'MultiPoint 多座席连接父功能',
    'SMB1Protocol':'旧 SMB1 父功能（不影响 SMB2/3 本身）',
    'MicrosoftWindowsPowerShellV2Root':'旧 PowerShell 2.0 父功能（保留 Windows PowerShell 5.1）',
    'Client-ProjFS':'开发工具投影文件系统',
    'Client-KeyboardFilter':'自助终端键盘过滤',
    'Client-UnifiedWriteFilter':'嵌入式统一写入过滤',
    'DataCenterBridging':'数据中心以太网流控',
    'DirectoryServices-ADAM-Client':'AD LDS 轻量目录服务',
    'SimpleTCP':'简单 TCP/IP 测试服务',
    'TelnetClient':'Telnet 客户端',
    'TFTP':'TFTP 客户端',
    'TIFFIFilter':'TIFF 文档搜索过滤器',
    'WorkFolders-Client':'企业工作文件夹同步',
    'SmbDirect':'SMB RDMA 文件共享（不是普通 TCP/IP 或 SMB2/3）',
    'Printing-PrintToPDFServices-Features':'PDF 虚拟打印',
    'Printing-XPSServices-Features':'XPS 虚拟打印',
    'Printing-Foundation-InternetPrinting-Client':'Internet 打印客户端',
    'Printing-Foundation-LPDPrintService':'LPD 打印服务',
    'Printing-Foundation-LPRPortMonitor':'LPR 打印端口',
}
parents = [('IIS-', 'IIS-WebServerRole'), ('WAS-', 'WAS-WindowsActivationService'),
           ('MSMQ-', 'MSMQ-Container'), ('MultiPoint-', 'MultiPoint-Connector'),
           ('SMB1', 'SMB1Protocol'), ('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root')]
deployment_only = {'BITS','wuauserv','UsoSvc','WaaSMedicSvc','DoSvc','TrustedInstaller','InstallService',
                   'AppXSvc','edgeupdate','edgeupdatem','DeviceInstall','DsmSvc'}
app_review = {'Microsoft.DesktopAppInstaller','Microsoft.WindowsStore','Microsoft.StorePurchaseApp'}
media_keep = {'Microsoft.HEVCVideoExtension','Microsoft.VP9VideoExtensions','Microsoft.WebMediaExtensions'}
sources = dict(baseline.get('Sources',{}))
sources.update({
 'feature_remove':'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-or-disable-windows-features-using-dism?view=windows-11',
 'service_guide':'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server',
 'cs2':'https://store.steampowered.com/app/730/CounterStrike_2/',
})
changes=[]
rows=[]
def change(row, rec, reason, impact=None, deps=None, group=None, purpose=None, evidence=None):
    row.update(Recommendation=rec,Reason=reason,Confidence='中')
    if impact: row['RemovalImpact']=impact
    if deps: row['Dependencies']=deps
    if group: row['Group']=group
    if purpose: row['Purpose']=purpose
    if evidence: row['Evidence']=evidence

for t in template['Components']:
    k=key(t); c=original[k]; r=copy.deepcopy(prior[k]); kind,n=k
    r['OriginalDetail']=c['Detail']; r['Protected']=c['Protected']
    if kind=='ProvisionedApp':
        app=c['Detail']
        if app=='Microsoft.VCLibs.140.00':
            change(r,'Keep','共享应用运行库；删除整个框架可能破坏部署/控制面板链路，清单无法排除其消费者。')
        elif app in app_review:
            change(r,'Review','比赛运行期不要求商店/winget；但显卡控制工具和部署方案尚未确定。确认已离线部署所需应用后可移除。静态镜像计划无法表达此阶段条件。',
                   '商店、MSIX/winget 或授权界面可能不可用；需核实选用的 NVIDIA 控制工具安装方式。',group='部署期 / 安装与分发条件')
        elif app in media_keep:
            change(r,'Review','不为播放器保留；需确认实际 Steam/CS2 媒体路径是否完全不调用此解码扩展后再移除。',
                   '删除解码扩展可能影响使用系统解码器的启动/媒体流程。',group='游戏链路 / 媒体依赖待验证')
        else:
            change(r,'Remove','比赛专机不需要此独立应用/扩展；接受对应桌面功能失效。移除应用不代表删除同类系统底层 API。',
                   '失去此条目描述的应用或扩展能力；只保证这是分析建议，尚未在该镜像中验证卸载/安装效果。',
                   '应用自身的框架/部署关系未完整导出；未识别到 CS2 本体对该独立应用的直接依赖。',
                   group='比赛外功能 / 应用移除')
    elif kind=='Feature':
        if n in feature_remove and c['Detail']!='Disabled with Payload Removed':
            change(r,'Remove',f'移除 {feature_remove[n]} 的可选载荷；目标只需 CS2/Steam，不为其他用途保留。原状态已禁用时收益主要是体积，并非已证实的帧率提升。',
                   '对应功能及子功能不能使用；是否实际释放载荷取决于共享包引用和 DISM 支持。',
                   '功能父子/共享包由 DISM 处理；不同时直接删除其 CBS 包或 WinSxS 目录。',
                   group='比赛外功能 / 可选功能载荷',evidence='功能标识与用途分析；DISM 支持 Disable-Feature /Remove。'+sources['feature_remove'])
        else:
            parent=next((p for prefix,p in parents if n.startswith(prefix) and n!=p),None)
            if n in {'ServicesForNFS-ClientOnly','NFS-Administration'}: parent='ClientForNFS-Infrastructure'
            if parent:
                change(r,'Keep','由父功能 '+parent+' 的操作负责；此行不重复提交子功能动作。Keep 仅指该行不单独操作。',
                       '父功能移除可能使本子功能不可用，这是本方案接受的结果。',group='可选功能 / 随父功能处理')
            elif n in {'WCF-TCP-PortSharing45'} and c['Detail']=='Enabled':
                change(r,'Disable','禁用 WCF 端口共享；CS2 专机不托管 WCF 服务器，保留 .NET 共享框架。',
                       'WCF TCP 端口共享不可用；不删除整个 .NET。')
            elif any(x in n for x in ['Hyper-V','Hypervisor','VirtualMachine','Containers','Subsystem-Linux','HostGuardian','ApplicationGuard']):
                change(r,'Keep','当前未启用，维持该状态。不能用删除该 Feature 来证明 VBS/反作弊依赖已核实；赛事反作弊的要求未知，不做跨层直接删除。')
            elif n in {'MediaPlayback','WindowsMediaPlayer'}:
                change(r,'Keep','保持媒体框架兼容路径；不安装/启动播放器应用。需要实际运行验证才能排除游戏/Steam 的媒体调用。')
    elif kind=='Capability':
        if c['Detail']=='Installed' and (n.startswith('Language.OCR~') or n.startswith('Microsoft.Windows.Notepad.System~')):
            change(r,'Remove','CS2 比赛不需要系统 OCR 或传统记事本；接受文字识别/文本编辑工具不可用。',
                   '无法使用此能力提供的文字识别或记事本；不移除中文基础输入和字体。',group='比赛外功能 / 可选能力')
        elif c['Detail']=='Not Present':
            change(r,'Keep','该能力未安装，不能重复移除；Keep 不会安装它。')
    elif kind=='Service':
        match=re.search(r'Start=(-?\d+); type=(\d+);',c['Detail'])
        start,typ=map(int,match.groups()) if match else (-1,0)
        if n == 'NetTcpPortSharing':
            change(r,'Keep','由 Feature WCF-TCP-PortSharing45 的禁用动作处理；此行不再重复禁用服务。',
                   '相应 WCF 端口共享功能会被禁用，这是方案接受的功能损失。',group='服务 / 随可选功能处理')
        elif n in extra_services and typ in {16,32,96,272}:
            title,impact=extra_services[n]
            change(r,'Keep' if start==4 else 'Disable',
                   '已经禁用，保持状态。' if start==4 else '比赛范围不需要'+title+'；关闭触发入口，保留服务注册项以便定位问题。禁用不保证提高 FPS。',
                   impact, title+' 对应消费者将不可用；精确服务依赖/触发器未导出，仍需组合启动测试。',
                   '比赛外功能 / 服务禁用',title+'；原始配置：'+c['Detail'],
                   '按服务身份和目标范围判断；未将 Windows Server 推荐直接当成 Windows 11 保证。'+sources['service_guide'])
        elif n in deployment_only:
            change(r,'Review','部署驱动、平台组件或 Steam 环境时可能需要。比赛前可按已验证流程冻结下载/维护，但当前静态动作无法表达“安装完成后再关闭”。',
                   '过早关闭可能导致设备安装、分发或部署失败。',group='部署期 / 比赛前冻结候选')
        elif n in {'WinDefend','WdNisSvc','SecurityHealthService','wscsvc','Sense','AppIDSvc'}:
            change(r,'Review','是否关闭安全/验证服务须结合赛事规则与实际反作弊要求；不能把兼容性牺牲解释成已验证的反作弊兼容。',
                   '可能影响安全状态检查或赛事软件接受该系统的条件；仅凭当前清单无法确定。',group='赛事条件 / 安全与反作弊待验证')
        elif n=='SysMain':
            change(r,'Review','极限性能需要在部署完成的实体机对比启用/禁用；缓存行为可能改善或损害冷启动/帧时间，不能预先承诺哪边更快。',group='性能实测 / 缓存策略')
        elif typ & 11:
            r['Reason']='保留必要硬件与内核链路的候选。缺少实际设备 ID、过滤堆栈和启动追踪，无法从驱动名称确认未被使用；不是为了通用硬件兼容而保留。'
    elif kind=='SystemApp':
        if any(x in n for x in ['BioEnrollment','CallingShellApp','PeopleExperienceHost','PrintQueueActionCenter','SecureAssessmentBrowser','XboxGameCallableUI','ParentalControls','narratorquickstart','ContentDeliveryManager','AssignedAccessLockApp','MicrosoftEdgeDevToolsClient']):
            change(r,'Review','表面功能超出比赛范围，属于进一步直接删目录的候选；缺少 manifest/反向引用和移除后启动证据，不能将其升级为已确认可执行。',
                   '若该目录被首次开机、Shell 或组件部署引用，可能导致安装/界面错误。',group='极限候选 / SystemApps 需验证')
        else:
            r['Reason']='此系统应用可能位于部署、登录或 Shell 链路；仅保留比赛启动环境的候选依赖，不为额外桌面体验作保证。'
    elif kind=='ComponentPayload':
        optional=any(x in r['Group'] for x in ['打印','虚拟化','企业可选','搜索','诊断'])
        if optional:
            change(r,'Review','该家族与比赛外功能相关，是进一步精简候选。需确认所属包及反向依赖后，从受支持的功能入口处理；不把家族关键词当作可删证明。',group='极限候选 / '+r['Group'])
        elif r['Recommendation']=='Keep':
            r['Reason']='其家族可能属于 CS2 的图形、音频、运行库、网络、输入或系统启动/部署链路。保留理由是功能依赖候选，而非通用桌面兼容。具体消费者尚待验证。'
    r['CanOmit']={'Remove':'建议移除，接受所列功能损失；尚未实体机验证。','Disable':'建议禁用，保留载荷/注册项；需验证组合影响。',
                  'Keep':'此条目不单独修改；不意味着启用或安装。','Review':'待核实/阶段性动作，不自动勾选；详见依据。'}[r['Recommendation']]
    r['PerformanceExpectation']='未进行 CS2 基准测试。区分功能裁剪、空间节省与帧时间收益；本文件不承诺 FPS 提升。'
    r['DependencyStatus']='功能关联分析；完整依赖图未提供，未进行实体机验证'
    if r['Recommendation']!=prior[k]['Recommendation']:
        changes.append((kind,n,prior[k]['Recommendation'],r['Recommendation']))
    rows.append(r)

report=copy.deepcopy(template)
report.update(IsTemplate=False,Components=rows,Profile=template['Profile']+' 本结果采用比赛专用激进裁剪；仅静态可表达且用途明确的动作进入 Remove/Disable。',
    SourceInventorySha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    SourceTemplateSha256=hashlib.sha256(template_path.read_bytes()).hexdigest(),Sources=sources,
    ValidationStatus='ExactIdentityAndActionValidationOnly_NotBootOrGameTested',
    Limitations=['本报告推断可用，未进行镜像构建、启动、CS2、驱动或反作弊实测。',
        '缺少网卡/音频/USB设备硬件 ID、赛事反作弊方案与实际依赖追踪；相应项目 Review。',
        'WinSxS 家族分组为名称推断，名称可能截断；不含完整 manifest 或硬链接关系。',
        'Stage-dependent 项不能直接在镜像里禁用，需部署完成后单独实测。',
        '未开启 Core。Keep/Review 不是保留锁，受父功能移除影响的条目会明确说明。'])
counts=collections.Counter(r['Recommendation'] for r in rows)
report['RecommendationCounts']=dict(counts)
assert len(rows)==len(original) and len({key(r) for r in rows})==len(original)
for r in rows:
    assert r['Recommendation'] in {'Keep','Remove','Disable','Review'}
    assert r['Recommendation']!='Disable' or r['Kind'] in {'Service','Feature'}
    if r['OriginalDetail'] in {'Not Present','Disabled with Payload Removed'}: assert r['Recommendation'] in {'Keep','Review'}
    for field in ['Purpose','Dependencies','RemovalImpact','Reason','Evidence']: assert r[field]
(out/'analysis.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
summary=['# CS2 线下比赛专用 · 激进分析','',report['Profile'],'',
 '这是候选构建方案，不是已实测的比赛镜像。全部 15,308 项与用户模板逐项对应；没有执行删除。','',
 '## 数量','', '| 建议 | 数量 |','|---|---:|']+[f'| {k} | {v} |' for k,v in counts.items()]+[
 '', '## 与上一版相比','', '| 类型 | 组件 | 原建议 | 当前建议 |','|---|---|---|---|']+[
 f'| {k} | `{n}` | {old} | {new} |' for k,n,old,new in changes]+[
 '', '## 本次会选择的动作','', '| 类型 | 组件 | 动作 | 影响 |','|---|---|---|---|']+[
 f"| {r['Kind']} | `{r['Identity']}` | {r['Recommendation']} | {r['RemovalImpact']} |" for r in rows if r['Recommendation'] in {'Remove','Disable'}]+[
 '', '## 保留/待核实的理由','',
 '- 图形、音频、内核、输入、网络、证书和运行库家族：比赛必需链路候选。',
 '- 商店/应用安装器：仅部署期候选；不因为日常用途保留。确认 NVIDIA 驱动工具离线安装路径后可进一步裁剪。',
 '- 更新/分发/设备安装服务：部署后冻结候选，避免提前破坏安装。',
 '- 防护/信任链：赛事反作弊未知，不能假定可以关闭。',
 '- SysMain 等缓存策略：需要重复帧时间实测。',
 '- WinSxS/SystemApps：具体反向依赖未知，不以删除数量替代可运行证据。',
 '', '## 建议的实体机验证顺序','',
 '1. Custom → List all components → Import analysis.json。Remove/Disable 建议会立即勾选并叠加到现有计划；Group/Core 保持原选择。',
 '2. 测试安装、首次启动、NVIDIA/AMD/网卡/声卡驱动安装和重启。',
 '3. 验证 Steam 登录/授权、CS2 DX11 启动、进入指定比赛服务器与重新连接。',
 '4. 验证鼠标键盘、显示刷新率、游戏声音与队伍语音；运行实际赛事反作弊。',
 '5. 与未裁剪基线进行相同场景多轮测试，记录帧时间、1% low、输入异常、崩溃和长时间稳定性。',
 '6. 部署完成后再逐项研究维护冻结/安全配置/缓存策略，不能把阶段性建议直接变成镜像删除动作。',
 '', '## 进一步精简需要补充的证据','',
 '- 实际网卡、音频和 USB 控制器硬件 ID、所用外设。',
 '- 赛事平台/反作弊名称与系统要求。',
 '- 目标组件 manifest、所属包、文件/注册表和服务反向引用。',
 '- Steam/CS2/驱动安装及比赛运行时的实际依赖追踪和删除后的回归测试。',
 '', '## 资料边界','',
 '引用官方资料用于确认功能和操作机制；Windows Server 服务指南不被当成 Windows 11 的逐项兼容保证。',
 *['- '+k+': '+v for k,v in sources.items()]]
(out/'README.zh-CN.md').write_text('\n'.join(summary),encoding='utf-8')
page=(ROOT/'artifacts/component-analysis/goat-os-cs2-report.html').read_text(encoding='utf-8')
data=json.dumps(rows,ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
page=re.sub(r'(<script id="data" type="application/json">).*?(</script>)',lambda m:m[1]+data+m[2],page,flags=re.S)
page=page.replace('goat-os-cs2-analysis.json','analysis.json').replace('CS2 专用组件分析','CS2 线下比赛 · 激进分析')
(out/'report.html').write_text(page,encoding='utf-8')
print(json.dumps({'counts':counts,'changed':len(changes),'total':len(rows),'actions':counts['Remove']+counts['Disable']},ensure_ascii=False))
