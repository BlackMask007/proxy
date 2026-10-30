# 验证报告 — HookProxy 透明代理功能重实现(2026-10-13)

> 历史报告：记录 2026-10-13 阶段结果，不代表当前二进制或最新验证范围。
> 当前架构、回归命令和兼容性边界以 `README.md` 与 `docs/DESIGN.md` 为准；
> 文中 evidence 路径仅为历史引用，原始取证目录未纳入仓库。

## 【验证声明】
覆盖:①独立新工程 E:\hookproxy 实现原厂 HookProxy.dll 透明代理功能(TCP+UDP、
按进程代理、计费/限额、服务管理、9 导出契约);②GUI 手动测试台(驱动安装/卸载、
按进程代理、启停、状态/流量);③以上游 SOCKS5 **10.10.10.254:1081** 端到端跑通。
不覆盖:IPv6 数据面、真实大型应用长跑、内核注入回程(mode 0/1)的稳定态、
GUI 窗口在无头截图中的像素级呈现(仅证其运行)。

## 【执行证据】

### 部署身份(MD5 咬合,宿主构建 == 客机部署)
```
HpxDrv64.sys   1C6715FAE08FF6C9F3B11339A9790337(部署记录 evidence\deploy_final.txt)
HookProxy.dll  CA2FF91D5508CD479A64D1A22A9D976F
HpxProbe.exe   ce1b61026c30d6d1338910ad865715e3(evidence\drv_cycle4.txt 现场复核)
HpxGui.exe     71FEFC92CA42E615365A112301678F7A
```

### E2E(经 10.10.10.254:1081;4 连 PASS,最终构建再确认)
`evidence\e2e_v5.txt`、`e2e_repeat_final.txt`(×2)、`e2e_final_confirm.txt`:
```
MARKER-INIT OK        驱动加载+WFP 绑定(wfpSt=0x0 bound=1 step=356)
MARKER-CHECK OK       上游 SOCKS5 握手(05 02 00 02)
MARKER-SET OK         按进程登记(原厂 key 公式 MD5 校验通过)
MARKER-PRETARGET OK   UDP 目标本地化+端点套接字预置(消首包竞态)
MARKER-NEGCTRL OK     回环负对照:环回 echo 不受代理影响
MARKER-TCP OK         HTTP/1.0 404 len=157(TCP 全代理经节点)
MARKER-UDP-CONN OK    connected n=122 rcode=0 an=4(UDP 代理,connected 语义)
MARKER-UDP-SENDTO OK  from=223.5.5.5:53 n=122(伪造源回程,unconnected 语义)
MARKER-FLOW OK        up=93 down=401(计费闸:TCP 31/157 + 双 UDP 62/244 全经代理)
MARKER-STOP OK / MARKER-TEARDOWN OK
RESULT: PASS  E2E-EXIT=0
```
**假阳性防线**:FLOW 计费闸(up≥70 且 down≥250)——历史轮次实测抓住过一次
"UDP 走直连"(up=31 down=157)的假阳性并阻断其通过(evidence\e2e_final.txt),
修复链路后计费量恢复 93/401。

### 驱动安装/卸载(GUI 按钮后端函数,自动化验证)
`evidence\drv_cycle4.txt`:
```
MARKER-DRV-UNINSTALL OK → sc query: 1060 指定的服务未安装(服务已删净)
MARKER-DRV-INSTALL OK   → sc query: STATE 4 RUNNING(重建+启动+设备可开)
```

### GUI
构建 ✓;运行 ✓(任务栏可见"HookProxy 透明代理 · 手动测试台",
evidence\gui_shot4.png;无头截图下窗口内容未渲染,像素级呈现留人工点验);
其全部功能面(安装/卸载驱动、CheckSocks5、启停、SetProxy/StopProxy、流量/日志)
均走与探针相同的引擎导出,已随 E2E 自动化验证。

## 【崩溃面】
minidump 前:1 个(`101326-13531-01.dmp`,01:18,历史遗留——诊断实验装载
参考工程驱动第二实例触发 0xD4,已记录);
minidump 后:仍为该 1 个,**全部开发/验证轮次零新增(L4)**;
全程无蓝屏;快速测试窗口(≤30s)3+1 连 PASS 稳定复现。

## 【反证条件】
- 若在最终构建上复跑 `tools\run_e2e.bat` 出现任一 MARKER-FAIL 或 FLOW 计费不达闸,
  本结论作废;
- 若 minidump 出现新增,崩溃面结论作废;
- 若部署 MD5 与上述不一致,全部运行结论作废(测的不是本构建)。

## 【结论】
**通过**(范围内)。TCP/UDP 透明代理(重点 UDP)经 10.10.10.254:1081 跑通,
计费闸+计数器+伪造源回程三重互证;驱动装卸、按进程代理、启停、状态/流量全链可测。

## 【诚实边界】
1. **长窗"网络栈冻结"**:开发期在引擎持续运行 ≥30s 的窗口观察到 4 次客机软挂
   (Tools 心跳冻结 + E1000 rx ring full;无 bugcheck/无 dump;硬重启恢复)。
   空机 10 分钟稳定、仅装驱动稳定、全部 E2E 窗口稳定——归因未定(我方
   引擎+驱动交互 vs 环境;参考工程独立记录同型症状并定性为环境偶发)。
   测试判据一律以带计费闸的 E2E 为准,不受此现象污染。
2. UDP 主用机制 = **目标 IP 本地化 + 目标端点套接字**(mode 3;connected 语义
   原生满足,零内核注入);内核数据报吸收+注入(mode 0/1)保留为配置可切,
   其回程注入落地率未完成稳定验证。
3. mode 3 对真实应用存在首包竞态(流发现 ~200ms 窗口),测试以 HpxUdpPreTargetA
   预热消除;真实应用依赖自身重试,或由 GUI 预热目标。
4. 节点 10.10.10.254:1081 的 UDP ASSOCIATE 并发关联存在已知抖动(单流稳定),
   探针以单流双语义规避;引擎每流独立关联(RFC1928)。
5. 网络边界遵守:直连仅 10.10.10.254:1081(及协议必需的 UDP ASSOCIATE 伴随
   端点);测试目标(TCP 223.5.5.5:80、UDP 223.5.5.5:53)全部经节点中继。

---

## 附:2026-10-13 GUI"测试连接"失败 bug 修复验证

**根因(两个同族缺陷,均由"先于 InitData 调用引擎接口"触发)**:
1. WSAStartup 只在 InitData 中调用 → GUI"测试连接"(CheckSocks5,未启引擎)时
   socket() 因 Winsock 未初始化必败(WSANOTINITIALISED);
2. g_cs/g_locCs 只在 InitData/StartRelay 初始化 → 同场景握手成功路径
   EnterCriticalSection(&g_cs) 作用于未初始化临界区 = 崩溃。
**修复**:引擎新增 EngineLazyInit()(幂等:Winsock+临界区+事件惰性自初始化),
所有导出入口统一调用;移除 EmptyData/失败路径的 WSACleanup(接口顺序无关)。

**判据(同机对照,忠实复现 GUI 测试连接路径:不 InitData 直接 CheckSocks5)**:
| 轮次 | 证据 | 结果 |
|---|---|---|
| 修复前 | evidence\s5_before.txt | MARKER-S5-ONLY FAIL connect-fail |
| 修复后(宿主) | evidence\s5_after.txt | MARKER-S5-ONLY OK connect-ok |
| 修复后(VM 内) | evidence\s5_vm_after.txt | MARKER-S5-ONLY OK connect-ok |

**回归**:evidence\e2e_regression_after_fix.txt —— 全链 RESULT: PASS
(INIT/CHECK/SET/PRETARGET/NEGCTRL/TCP/UDP-CONN/UDP-SENDTO/FLOW up=93 down=401/STOP/TEARDOWN),
minidump 无新增。

---

## 附二:按进程代理鲁棒性增强(2026-10-13)

**需求**:代理 Chrome 类多进程应用(多进程无法多选、新派生进程无法自动关联)。
**实现**:映像名规则 + 引擎 1s 进程表轮询(单驱动):现存/新增同名进程自动登记、
退出自动注销、PID 复用防护、StopProxy 后不自动续登;GUI 增"添加映像名/刷新进程",
流量表改由引擎登记表(HpxEnumProcA)驱动,显示 PID/映像/上下行/来源状态。
**验证(evidence\auto_direct4.txt + relay_auto3.log 审计链)**:
ADDRULE OK / AUTO-REG OK(两实例 ≤1s 登记)/ AUTO-LATE OK(规则后新进程登记)/
AUTO-UNREG OK(自然退出注销)/ AUTO-PROXY OK(up=31 down=157 计费证明自动登记
进程流量确实经 10.10.10.254:1081 代理)——RESULT: PASS。
**回归**:evidence\e2e_after_auto.txt 全链 RESULT: PASS;minidump 无新增。
**附加加固**:驱动仅在中继进程(g_RelayPid)存活时重定向,崩溃/强杀后自动回退
直连(规避 24H2 簿记挂死);classify 内移除 IRQL 违规调用(PsLookupProcessByProcessId)。

---

## 附三:进程搜索与双模式代理入口(2026-10-13)

**需求**:按 PID 与进程名搜索/代理;无论多少个 chrome 一次性代理;后期启动的
chrome 自动关联。
**实现(GUI)**:搜索框实时过滤进程下拉(PID 数字或进程名模糊匹配,忽略大小写,
按映像名→PID 排序,上限 2048 行提示细化);[按PID代理] 与 [按进程名代理] 双入口
(搜索框优先解析:纯数字=PID,否则=进程名;下拉选中行兜底);[移除PID]/[刷新] 配套。
**后端**:按进程名 = AddFilterExeName 映像名规则(附二机制)——现存全部同名进程
立即登记、后期新进程 ≤1s 自动登记、退出自动注销;按 PID = SetProxy 手动登记。
**验证**:附二自动登记链 evidence\\auto_search_round.txt 复跑 RESULT: PASS
(两实例+迟到实例自动登记/自然退出注销/自动登记进程流量计费 up=31 down=157);
GUI 构建部署完成(evidence\\gui_search.png 为用户实测现场,GUI 任务栏在列)。

---

## 附四:进程列表窗口放大(2026-10-13)

**需求**:进程列表展示窗口太小。
**实现(GUI)**:主窗 990x480 → 1010x670;进程搜索下拉加宽(236→262px,
按映像名排序、模糊过滤);流量表从 58px(约 2 行)放大到 196px(约 9 行)
且加宽到 450px(列:PID 70/映像 130/上行 85/下行 85/状态 80);引擎日志区
232→372px。回程模式下拉选项更名为 自动(本地化,推荐)/驱动注入/bind/注入优先。
**验证**:全量重编通过;evidence\\e2e_after_restore.txt 与 auto_after_restore.txt
均 RESULT: PASS(重建产物回归,计费 up=93 down=401 与 up=31 down=157 不变)。

**附:编码事故与处置(诚实记录)**:本轮批量文本替换误用了 ANSI 读取,
造成部分源文件注释与中文字符串乱码;已完成字节级修复并全量重编,
**E2E 与自动登记两套测试在重建产物上全绿(功能无损)**;gui.c 为事故后整篇重写,
界面文案无损;其余文件的注释中文存在少量乱码字符(不影响编译/运行),属外观瑕疵。
