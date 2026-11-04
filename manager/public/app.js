/* global fetch, URLSearchParams */

'use strict';

/* =========================================================================
   Utilities
   ========================================================================= */

const appEl = document.getElementById('app');
const toastRoot = document.getElementById('toast-root');
const modalRoot = document.getElementById('modal-root');
const drawerRoot = document.getElementById('drawer-root');

const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ESC_MAP[ch]);
const icon = (name, cls = '') =>
  `<svg class="icon ${cls}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;

const LOCALES = { en: 'en-US', id: 'id-ID', zh: 'zh-CN', ar: 'ar-SA', ja: 'ja-JP' };
const I18N = {
  en: {
    eventsSub: "ModSecurity events from the audit log. Click a row to view triggered rules.", rulesSub: "OWASP Core Rule Set rules detected in the engine.", customSub: "Additional rules beyond CRS, loaded before CRS detection rules.", exclusionsSub: "Exclude specific CRS rules for URI path, hostname, or all traffic.", ipListsSub: "Client IP allowlist and blocklist. Allowlist always takes precedence over blocklist.", proxySub: "Manage upstreams by hostname or public port. All traffic still passes through ModSecurity.", testSub: "Send requests through the WAF to verify rule matches and blocking behavior.", settingsSub: "ModSecurity engine configuration, CRS tuning, and system maintenance.", thTime: "Time", thAction: "Action", thIp: "Client IP", thRequest: "Request", thStatus: "Status", thRule: "Rule", thSeverity: "Severity", thPl: "PL", thPhase: "Phase", thFile: "File", thActive: "Active", thName: "Name", thCondition: "Condition", thScope: "Scope", thTarget: "Target", thRuleId: "Rule ID", thNote: "Note", thPort: "Public port", thUpstream: "Upstream", thWaf: "WAF", thHit: "Hits", allActions: "All actions", allSeverities: "All severities", allStatuses: "All statuses", allPl: "All PL", allRanges: "All", searchEvents: "Search IP, URI, user-agent, or rule…", searchRules: "Search ID, message, or tag…", apply: "Apply", prev: "Previous", next: "Next", save: "Save", cancel: "Cancel", delete: "Delete", edit: "Edit", close: "Close", add: "Add", retry: "Try again", viewFiles: "Configuration files", testRule: "Test rule", newCustom: "Custom rule", newExclusion: "New exclusion", newSite: "New site", checkProxy: "Check integration", saveUpstream: "Save upstream", saveRateLimit: "Save rate limit", saveThreatIntel: "Save configuration", saveRetention: "Save retention", saveErrorPages: "Save error pages", saveAndReload: "Save & reload", sendRequest: "Send request", pruneNow: "Prune now", syncNow: "Sync now", checkUpdate: "Check for updates", updateCrs: "Update CRS", restartContainer: "Restart container", reloadWaf: "Reload WAF", defaultUpstream: "Default upstream", howItWorks: "How it works", virtualHost: "Virtual host", entries: "entries", noEntries: "No entries yet.", pageOf: "Page", of: "of", noRulesFound: "No rules found", noRulesMatch: "No rules match the selected filter.", noCustomFound: "No custom rules yet", noCustomSub: "Create your first custom rule to add application-specific protection.", noExclFound: "No exclusions yet", noExclSub: "All CRS rules are operating according to configuration.", noSitesFound: "No virtual hosts yet", noSitesSub: "All requests are currently routed to the default upstream. Add a site to route by hostname or port.", noTestFound: "No request sent yet", noTestSub: "Choose a preset or enter a custom request, then click Send request.", noEventsFilter: "No events match the current filter. Try changing the time range or sending requests through the WAF.",
    language: 'Language', theme: 'Theme', auto: 'Auto', light: 'Light', dark: 'Dark',
    console: 'Management console', navigation: 'Main navigation', monitor: 'Monitor', protection: 'Protection', tools: 'Tools',
    dashboard: 'Dashboard', events: 'Audit Events', rules: 'CRS Rules', custom: 'Custom Rules', exclusions: 'Exclusions',
    ipLists: 'IP Lists', proxy: 'Reverse Proxy', test: 'Test Console', settings: 'Settings', checking: 'checking…', sites: 'sites',
    reload: 'Reload', logout: 'Log out', collapse: 'Collapse sidebar', expand: 'Expand sidebar',
    loginTitle: 'Sign in to the panel', loginLead: 'Use the administrator password provided during installation.',
    loginHero: 'Control your WAF and reverse proxy from one panel.',
    loginCopy: 'Manage OWASP Core Rule Set rules, exclusions, custom rules, IP lists, application upstreams, and audit logs without editing configuration files manually.',
    adminPassword: 'Administrator password', enterPassword: 'Enter password', showPassword: 'Show password', signIn: 'Sign in',
    passwordRequired: 'Password is required.', verifying: 'Verifying…', defaultPassword: 'The default password <strong>admin</strong> is still active. Set <span class="mono">OPENWAF_ADMIN_PASSWORD</span> in the <span class="mono">.env</span> file immediately.',
    loading: 'Loading data…', blocked: 'Blocked', detected: 'Detected', allowed: 'Allowed',
    dashSubtitle: 'A summary of WAF health, inspected traffic, and recent threats.', refresh: 'Refresh', testRequest: 'Test request',
    audit24: 'Audit events · 24 hours', uniqueIps: 'unique IPs', passed: 'allowed', blocked24: 'Blocked · 24 hours',
    totalEvents: 'of all events', detectedOnly: 'Detection only', anomalyHint: 'Anomaly score has not reached the threshold',
    disabled: 'disabled', customShort: 'custom', eventTrend: '24-hour event trend', eventTrendSub: 'Blocked, detected, and allowed per hour',
    allEvents: 'All events', wafStatus: 'WAF status', unavailable: 'unavailable', containerName: 'Container name', engineMode: 'Engine mode',
    auditEngine: 'Audit engine', paranoia: 'Paranoia level', threshold: 'Threshold', crsVersion: 'CRS version', auditLog: 'Audit log',
    topRules: 'Most triggered rules', last24: 'Last 24 hours', openRules: 'Open rules', topIps: 'Top client IPs', basedAudit: 'Based on audit events',
    latestEvents: 'Latest events', clickDetail: 'Click a row to view audit-log details', time: 'Time', action: 'Action', request: 'Request', status: 'Status', rule: 'Rule',
    noEvents: 'No events yet', noEventsText: 'The audit log is empty. Send traffic through the WAF to see events here.', viewAll: 'View all',
    noRule: 'No rules have been triggered.', noIp: 'No client IP data yet.', defaultWarning: 'The default password is still in use. Set <span class="mono">OPENWAF_ADMIN_PASSWORD</span>.',
    eventsIn24h: 'events in 24 hours', validateAndReload: 'Validate and reload WAF',
  },
  id: {
    eventsSub: "Event ModSecurity dari audit log. Klik baris untuk melihat rule yang terpicu.", rulesSub: "Rule OWASP Core Rule Set yang terdeteksi di engine.", customSub: "Rule tambahan di luar CRS, dibaca sebelum rule deteksi CRS.", exclusionsSub: "Kecualikan rule CRS tertentu untuk path URI, host, atau semua trafik.", ipListsSub: "Allowlist dan blocklist client IP. Allowlist selalu menang atas blocklist.", proxySub: "Kelola upstream berdasarkan hostname atau port publik. Semua trafik tetap melewati ModSecurity.", testSub: "Kirim request melalui WAF untuk memverifikasi rule dan perilaku proteksi.", settingsSub: "Konfigurasi engine ModSecurity, tuning CRS, dan pemeliharaan sistem.", thTime: "Waktu", thAction: "Aksi", thIp: "Client IP", thRequest: "Request", thStatus: "Status", thRule: "Rule", thSeverity: "Severity", thPl: "PL", thPhase: "Phase", thFile: "File", thActive: "Aktif", thName: "Nama", thCondition: "Kondisi", thScope: "Scope", thTarget: "Target", thRuleId: "Rule ID", thNote: "Catatan", thPort: "Port publik", thUpstream: "Upstream", thWaf: "WAF", thHit: "Hit", allActions: "Semua aksi", allSeverities: "Semua severity", allStatuses: "Semua status", allPl: "Semua PL", allRanges: "Semua", searchEvents: "Cari IP, URI, user-agent, atau rule…", searchRules: "Cari ID, pesan, atau tag…", apply: "Terapkan", prev: "Sebelumnya", next: "Berikutnya", save: "Simpan", cancel: "Batal", delete: "Hapus", edit: "Edit", close: "Tutup", add: "Tambah", retry: "Coba lagi", viewFiles: "Lihat file konfigurasi", testRule: "Test rule", newCustom: "Custom rule", newExclusion: "Exclusion baru", newSite: "Situs baru", checkProxy: "Cek integrasi", saveUpstream: "Simpan upstream", saveRateLimit: "Simpan rate limit", saveThreatIntel: "Simpan konfigurasi", saveRetention: "Simpan retensi", saveErrorPages: "Simpan error pages", saveAndReload: "Simpan & reload", sendRequest: "Kirim request", pruneNow: "Prune sekarang", syncNow: "Sinkronkan sekarang", checkUpdate: "Periksa update", updateCrs: "Update CRS", restartContainer: "Restart container", reloadWaf: "Reload WAF", defaultUpstream: "Upstream default", howItWorks: "Cara kerja", virtualHost: "Virtual host", entries: "entri", noEntries: "Belum ada entri.", pageOf: "Halaman", of: "dari", noRulesFound: "Tidak ada rule", noRulesMatch: "Tidak ada rule yang cocok dengan filter yang dipilih.", noCustomFound: "Belum ada custom rule", noCustomSub: "Buat rule pertama untuk menambahkan proteksi khusus aplikasi Anda.", noExclFound: "Belum ada exclusion", noExclSub: "Semua rule CRS berjalan sesuai konfigurasi.", noSitesFound: "Belum ada virtual host", noSitesSub: "Semua request saat ini diteruskan ke upstream default. Tambahkan situs untuk routing berdasarkan hostname atau port.", noTestFound: "Belum ada request", noTestSub: "Pilih preset atau tulis request sendiri, lalu klik Kirim request.", noEventsFilter: "Belum ada audit event yang cocok dengan filter. Coba ubah rentang waktu atau hasilkan request ke WAF.",
    language: 'Bahasa', theme: 'Tema', auto: 'Otomatis', light: 'Terang', dark: 'Gelap', console: 'Konsol manajemen', navigation: 'Navigasi utama',
    monitor: 'Monitor', protection: 'Proteksi', tools: 'Alat', dashboard: 'Dasbor', events: 'Audit Events', rules: 'CRS Rules', custom: 'Custom Rules', exclusions: 'Exclusions', ipLists: 'IP Lists', proxy: 'Reverse Proxy', test: 'Test Console', settings: 'Pengaturan', checking: 'memeriksa…', sites: 'situs', reload: 'Muat ulang', logout: 'Keluar', collapse: 'Minimalkan sidebar', expand: 'Perluas sidebar',
    loginTitle: 'Masuk ke panel', loginLead: 'Gunakan password administrator yang diberikan saat instalasi.', loginHero: 'Kendalikan WAF dan reverse proxy dari satu panel.', loginCopy: 'Kelola aturan OWASP Core Rule Set, exclusion, custom rule, IP list, upstream aplikasi, dan audit log tanpa mengedit konfigurasi secara manual.', adminPassword: 'Password administrator', enterPassword: 'Masukkan password', showPassword: 'Tampilkan password', signIn: 'Masuk', passwordRequired: 'Password wajib diisi.', verifying: 'Memeriksa…', defaultPassword: 'Password default <strong>admin</strong> masih aktif. Segera set <span class="mono">OPENWAF_ADMIN_PASSWORD</span> di file <span class="mono">.env</span>.', loading: 'Memuat data…', blocked: 'Diblokir', detected: 'Terdeteksi', allowed: 'Lolos', dashSubtitle: 'Ringkasan kondisi WAF, trafik yang diperiksa, dan ancaman terbaru.', refresh: 'Refresh', testRequest: 'Test request', audit24: 'Audit event · 24 jam', uniqueIps: 'IP unik', passed: 'lolos', blocked24: 'Diblokir · 24 jam', totalEvents: 'dari total event', detectedOnly: 'Terdeteksi saja', anomalyHint: 'Skor anomali belum mencapai threshold', disabled: 'nonaktif', customShort: 'custom', eventTrend: 'Tren event 24 jam', eventTrendSub: 'Diblokir, terdeteksi, dan lolos per jam', allEvents: 'Semua event', wafStatus: 'Status WAF', unavailable: 'tidak tersedia', containerName: 'Nama container', engineMode: 'Mode engine', auditEngine: 'Audit engine', paranoia: 'Paranoia level', threshold: 'Threshold', crsVersion: 'Versi CRS', auditLog: 'Audit log', topRules: 'Rule paling sering terpicu', last24: '24 jam terakhir', openRules: 'Buka rules', topIps: 'Client IP teratas', basedAudit: 'Berdasarkan audit event', latestEvents: 'Event terbaru', clickDetail: 'Klik baris untuk melihat detail audit log', time: 'Waktu', action: 'Aksi', request: 'Request', status: 'Status', rule: 'Rule', noEvents: 'Belum ada event', noEventsText: 'Audit log masih kosong. Hasilkan trafik ke WAF untuk melihat event di sini.', viewAll: 'Lihat semua', noRule: 'Belum ada rule terpicu.', noIp: 'Belum ada data client IP.', defaultWarning: 'Password default masih dipakai. Set <span class="mono">OPENWAF_ADMIN_PASSWORD</span>.',
    eventsIn24h: 'event dalam 24 jam', validateAndReload: 'Validasi dan reload WAF',
  },
  zh: {
    eventsSub: "来自审计日志的 ModSecurity 事件。点击查看触发的规则。", rulesSub: "引擎中检测到的 OWASP Core Rule Set 规则。", customSub: "除 CRS 之外的附加规则，在 CRS 检测规则之前读取。", exclusionsSub: "针对 URI 路径、主机或全部流量排除特定 CRS 规则。", ipListsSub: "客户端 IP 白名单与黑名单。白名单优先于黑名单。", proxySub: "按主机名或公共端口管理上游应用。所有流量均经过 ModSecurity。", testSub: "通过 WAF 发送测试请求以验证拦截与规则匹配情况。", settingsSub: "ModSecurity 引擎配置、CRS 调优及系统维护。", thTime: "时间", thAction: "操作", thIp: "客户端 IP", thRequest: "请求", thStatus: "状态", thRule: "规则", thSeverity: "严重级别", thPl: "PL", thPhase: "阶段", thFile: "文件", thActive: "启用", thName: "名称", thCondition: "条件", thScope: "范围", thTarget: "目标", thRuleId: "规则 ID", thNote: "备注", thPort: "公共端口", thUpstream: "上游", thWaf: "WAF", thHit: "命中次数", allActions: "所有操作", allSeverities: "所有严重级别", allStatuses: "所有状态", allPl: "所有 PL", allRanges: "全部", searchEvents: "搜索 IP、URI、User-Agent 或规则…", searchRules: "搜索 ID、消息或标签…", apply: "应用", prev: "上一页", next: "下一页", save: "保存", cancel: "取消", delete: "删除", edit: "编辑", close: "关闭", add: "添加", retry: "重试", viewFiles: "配置文件", testRule: "测试规则", newCustom: "自定义规则", newExclusion: "新建排除项", newSite: "新建站点", checkProxy: "检查集成", saveUpstream: "保存上游", saveRateLimit: "保存速率限制", saveThreatIntel: "保存威胁情报", saveRetention: "保存保留设置", saveErrorPages: "保存错误页", saveAndReload: "保存并重新加载", sendRequest: "发送请求", pruneNow: "立即清理", syncNow: "立即同步", checkUpdate: "检查更新", updateCrs: "更新 CRS", restartContainer: "重启容器", reloadWaf: "重载 WAF", defaultUpstream: "默认上游", howItWorks: "工作原理", virtualHost: "虚拟主机", entries: "条目", noEntries: "暂无条目。", pageOf: "页码", of: "/", noRulesFound: "未找到规则", noRulesMatch: "没有匹配所选筛选条件的规则。", noCustomFound: "暂无自定义规则", noCustomSub: "创建您的第一条自定义规则以增强针对应用的特定防护。", noExclFound: "暂无排除项", noExclSub: "所有 CRS 规则均按默认配置正常运行。", noSitesFound: "暂无虚拟主机", noSitesSub: "所有请求当前均路由至默认上游。添加站点可基于域名或端口分发。", noTestFound: "尚未发送请求", noTestSub: "选择预设或输入自定义请求，然后点击发送。", noEventsFilter: "没有符合筛选条件的审计事件。尝试调整时间范围或向 WAF 发送流量。", language:'语言',theme:'主题',auto:'自动',light:'浅色',dark:'深色',console:'管理控制台',navigation:'主导航',monitor:'监控',protection:'防护',tools:'工具',dashboard:'仪表盘',events:'审计事件',rules:'CRS 规则',custom:'自定义规则',exclusions:'排除项',ipLists:'IP 列表',proxy:'反向代理',test:'测试控制台',settings:'设置',checking:'检查中…',sites:'站点',reload:'重载',logout:'退出',collapse:'收起侧栏',expand:'展开侧栏',loginTitle:'登录管理面板',loginLead:'请输入安装时设置的管理员密码。',loginHero:'在一个面板中控制 WAF 和反向代理。',loginCopy:'无需手动编辑配置文件，即可管理 OWASP CRS、排除项、自定义规则、IP 列表、应用上游和审计日志。',adminPassword:'管理员密码',enterPassword:'输入密码',showPassword:'显示密码',signIn:'登录',passwordRequired:'请输入密码。',verifying:'验证中…',defaultPassword:'默认密码 <strong>admin</strong> 仍在使用。请立即在 <span class="mono">.env</span> 中设置 <span class="mono">OPENWAF_ADMIN_PASSWORD</span>。',loading:'正在加载…',blocked:'已拦截',detected:'已检测',allowed:'已放行',dashSubtitle:'WAF 状态、已检查流量和近期威胁摘要。',refresh:'刷新',testRequest:'测试请求',audit24:'审计事件 · 24 小时',uniqueIps:'唯一 IP',passed:'已放行',blocked24:'已拦截 · 24 小时',totalEvents:'占全部事件',detectedOnly:'仅检测',anomalyHint:'异常分数尚未达到阈值',disabled:'已禁用',customShort:'自定义',eventTrend:'24 小时事件趋势',eventTrendSub:'每小时拦截、检测和放行',allEvents:'全部事件',wafStatus:'WAF 状态',unavailable:'不可用',containerName:'容器名称',engineMode:'引擎模式',auditEngine:'审计引擎',paranoia:'防护等级',threshold:'阈值',crsVersion:'CRS 版本',auditLog:'审计日志',topRules:'最常触发的规则',last24:'最近 24 小时',openRules:'打开规则',topIps:'热门客户端 IP',basedAudit:'基于审计事件',latestEvents:'最新事件',clickDetail:'点击行查看审计日志详情',time:'时间',action:'操作',request:'请求',status:'状态',rule:'规则',noEvents:'暂无事件',noEventsText:'审计日志为空。请向 WAF 发送流量。',viewAll:'查看全部',noRule:'尚未触发规则。',noIp:'暂无客户端 IP 数据。',defaultWarning:'默认密码仍在使用，请设置 <span class="mono">OPENWAF_ADMIN_PASSWORD</span>。',eventsIn24h:'24 小时内的事件',validateAndReload:'验证并重载 WAF' },
  ar: {
    eventsSub: "أحداث ModSecurity من سجل التدقيق. انقر على صف لعرض القواعد التي تم تشغيلها.", rulesSub: "قواعد OWASP Core Rule Set المكتشفة في المحرك.", customSub: "قواعد إضافية تُقرأ قبل قواعد اكتشاف CRS.", exclusionsSub: "استبعاد قواعد CRS معينة لمسار أو مضيف أو كل حركة المرور.", ipListsSub: "القائمة المسموح بها والمحظورة لعناوين IP. الأولوية دائمًا للقائمة المسموح بها.", proxySub: "إدارة التطبيقات الخلفية حسب اسم المضيف أو المنفذ العام.", testSub: "إرسال طلبات عبر WAF للتحقق من مطابقة القواعد وسلوك الحظر.", settingsSub: "تكوين محرك ModSecurity وضبط CRS وصيانة النظام.", thTime: "الوقت", thAction: "الإجراء", thIp: "عنوان IP", thRequest: "الطلب", thStatus: "الحالة", thRule: "القاعدة", thSeverity: "الخطورة", thPl: "PL", thPhase: "المرحلة", thFile: "الملف", thActive: "نشط", thName: "الاسم", thCondition: "الشرط", thScope: "النطاق", thTarget: "الهدف", thRuleId: "معرف القاعدة", thNote: "ملاحظة", thPort: "المنفذ العام", thUpstream: "الخلفية", thWaf: "WAF", thHit: "المرات", allActions: "كل الإجراءات", allSeverities: "كل درجات الخطورة", allStatuses: "كل الحالات", allPl: "كل PL", allRanges: "الكل", searchEvents: "بحث عن IP أو مسار أو وكيل مستخدم أو قاعدة…", searchRules: "بحث عن معرف أو رسالة أو وسم…", apply: "تطبيق", prev: "السابق", next: "التالي", save: "حفظ", cancel: "إلغاء", delete: "حذف", edit: "تعديل", close: "إغلاق", add: "إضافة", retry: "إعادة المحاولة", viewFiles: "ملفات التكوين", testRule: "اختبار القاعدة", newCustom: "قاعدة مخصصة", newExclusion: "استثناء جديد", newSite: "موقع جديد", checkProxy: "فحص التكامل", saveUpstream: "حفظ الخلفية", saveRateLimit: "حفظ حد المعدل", saveThreatIntel: "حفظ معلومات التهديدات", saveRetention: "حفظ الاحتفاظ", saveErrorPages: "حفظ صفحات الخطأ", saveAndReload: "حفظ وإعادة تحميل", sendRequest: "إرسال الطلب", pruneNow: "تنظيف الآن", syncNow: "مزامنة الآن", checkUpdate: "التحقق من التحديثات", updateCrs: "تحديث CRS", restartContainer: "إعادة تشغيل الحاوية", reloadWaf: "إعادة تحميل WAF", defaultUpstream: "الخلفية الافتراضية", howItWorks: "كيف يعمل", virtualHost: "المضيف الافتراضي", entries: "إدخالات", noEntries: "لا توجد إدخالات بعد.", pageOf: "صفحة", of: "من", noRulesFound: "لم يتم العثور على قواعد", noRulesMatch: "لا توجد قواعد تطابق التصفية المحددة.", noCustomFound: "لا توجد قواعد مخصصة بعد", noCustomSub: "أنشئ قاعدتك المخصصة الأولى لحماية تطبيقك.", noExclFound: "لا توجد استثناءات بعد", noExclSub: "تعمل جميع قواعد CRS وفقًا للتكوين.", noSitesFound: "لا توجد مضيفات افتراضية", noSitesSub: "يتم توجيه جميع الطلبات حاليًا إلى الخلفية الافتراضية.", noTestFound: "لم يتم إرسال طلب بعد", noTestSub: "اختر إعدادًا مسبقًا أو اكتب طلبًا مخصصًا ثم انقر فوق إرسال.", noEventsFilter: "لا توجد أحداث تدقيق مطابقة. حاول تغيير النطاق الزمني أو إرسال حركة مرور.", language:'اللغة',theme:'المظهر',auto:'تلقائي',light:'فاتح',dark:'داكن',console:'لوحة الإدارة',navigation:'التنقل الرئيسي',monitor:'المراقبة',protection:'الحماية',tools:'الأدوات',dashboard:'لوحة المعلومات',events:'سجل التدقيق',rules:'قواعد CRS',custom:'قواعد مخصصة',exclusions:'الاستثناءات',ipLists:'قوائم IP',proxy:'الوكيل العكسي',test:'وحدة الاختبار',settings:'الإعدادات',checking:'جارٍ الفحص…',sites:'مواقع',reload:'إعادة تحميل',logout:'تسجيل الخروج',collapse:'طي الشريط الجانبي',expand:'توسيع الشريط الجانبي',loginTitle:'تسجيل الدخول إلى اللوحة',loginLead:'استخدم كلمة مرور المسؤول المحددة أثناء التثبيت.',loginHero:'تحكم في WAF والوكيل العكسي من لوحة واحدة.',loginCopy:'أدر قواعد OWASP CRS والاستثناءات والقواعد المخصصة وقوائم IP وسجلات التدقيق دون تعديل ملفات الإعداد يدويًا.',adminPassword:'كلمة مرور المسؤول',enterPassword:'أدخل كلمة المرور',showPassword:'إظهار كلمة المرور',signIn:'دخول',passwordRequired:'كلمة المرور مطلوبة.',verifying:'جارٍ التحقق…',defaultPassword:'كلمة المرور الافتراضية <strong>admin</strong> ما زالت فعالة. عيّن <span class="mono">OPENWAF_ADMIN_PASSWORD</span> في ملف <span class="mono">.env</span>.',loading:'جارٍ تحميل البيانات…',blocked:'محظور',detected:'مكتشف',allowed:'مسموح',dashSubtitle:'ملخص حالة WAF وحركة المرور والتهديدات الأخيرة.',refresh:'تحديث',testRequest:'اختبار طلب',audit24:'أحداث التدقيق · 24 ساعة',uniqueIps:'عناوين IP فريدة',passed:'مسموح',blocked24:'محظور · 24 ساعة',totalEvents:'من إجمالي الأحداث',detectedOnly:'اكتشاف فقط',anomalyHint:'لم تصل درجة الشذوذ إلى الحد',disabled:'معطل',customShort:'مخصص',eventTrend:'اتجاه الأحداث خلال 24 ساعة',eventTrendSub:'المحظور والمكتشف والمسموح كل ساعة',allEvents:'كل الأحداث',wafStatus:'حالة WAF',unavailable:'غير متاح',containerName:'اسم الحاوية',engineMode:'وضع المحرك',auditEngine:'محرك التدقيق',paranoia:'مستوى الحماية',threshold:'الحد',crsVersion:'إصدار CRS',auditLog:'سجل التدقيق',topRules:'القواعد الأكثر تشغيلًا',last24:'آخر 24 ساعة',openRules:'فتح القواعد',topIps:'أعلى عناوين IP',basedAudit:'بناءً على أحداث التدقيق',latestEvents:'أحدث الأحداث',clickDetail:'انقر على صف لعرض التفاصيل',time:'الوقت',action:'الإجراء',request:'الطلب',status:'الحالة',rule:'القاعدة',noEvents:'لا توجد أحداث',noEventsText:'سجل التدقيق فارغ. أرسل حركة مرور عبر WAF.',viewAll:'عرض الكل',noRule:'لم يتم تشغيل أي قاعدة.',noIp:'لا توجد بيانات IP.',defaultWarning:'كلمة المرور الافتراضية ما زالت مستخدمة. عيّن <span class="mono">OPENWAF_ADMIN_PASSWORD</span>.',eventsIn24h:'حدث خلال 24 ساعة',validateAndReload:'التحقق وإعادة تحميل WAF' },
  ja: {
    eventsSub: "監査ログからの ModSecurity イベント。行をクリックして発火したルールを確認。", rulesSub: "エンジンで検出された OWASP Core Rule Set ルール。", customSub: "CRS 検出ルールの前に読み込まれる追加ルール。", exclusionsSub: "URI パス、ホスト名、または全トラフィックに対して特定の CRS ルールを除外。", ipListsSub: "クライアント IP の許可リストおよび拒否リスト。許可リストが常に優先されます。", proxySub: "ホスト名または公開ポートごとにアップストリームを管理。すべてのトラフィックは WAF を経由します。", testSub: "WAF を通じてリクエストを送信し、ルールの発火とブロック動作を確認。", settingsSub: "ModSecurity エンジン設定、CRS チューニング、およびシステム保守。", thTime: "時刻", thAction: "アクション", thIp: "クライアント IP", thRequest: "リクエスト", thStatus: "状態", thRule: "ルール", thSeverity: "重大度", thPl: "PL", thPhase: "フェーズ", thFile: "ファイル", thActive: "有効", thName: "名前", thCondition: "条件", thScope: "スコープ", thTarget: "ターゲット", thRuleId: "ルール ID", thNote: "備考", thPort: "公開ポート", thUpstream: "アップストリーム", thWaf: "WAF", thHit: "ヒット", allActions: "すべてのアクション", allSeverities: "すべての重大度", allStatuses: "すべての状態", allPl: "すべての PL", allRanges: "すべて", searchEvents: "IP、URI、User-Agent、ルールを検索…", searchRules: "ID、メッセージ、タグを検索…", apply: "適用", prev: "前へ", next: "次へ", save: "保存", cancel: "キャンセル", delete: "削除", edit: "編集", close: "閉じる", add: "追加", retry: "再試行", viewFiles: "設定ファイルを表示", testRule: "ルールをテスト", newCustom: "カスタムルール", newExclusion: "新規除外設定", newSite: "新規サイト", checkProxy: "統合を確認", saveUpstream: "アップストリームを保存", saveRateLimit: "レート制限を保存", saveThreatIntel: "脅威インテリジェンスを保存", saveRetention: "保持期間を保存", saveErrorPages: "エラーページを保存", saveAndReload: "保存して再読み込み", sendRequest: "リクエスト送信", pruneNow: "今すぐクリーンアップ", syncNow: "今すぐ同期", checkUpdate: "更新を確認", updateCrs: "CRS を更新", restartContainer: "コンテナを再起動", reloadWaf: "WAF を再読み込み", defaultUpstream: "デフォルトアップストリーム", howItWorks: "動作の仕組み", virtualHost: "バーチャルホスト", entries: "件", noEntries: "エントリはありません。", pageOf: "ページ", of: "/", noRulesFound: "ルールが見つかりません", noRulesMatch: "選択したフィルタに一致するルールはありません。", noCustomFound: "カスタムルールはありません", noCustomSub: "アプリケーション固有の保護を追加するためにルールを作成してください。", noExclFound: "除外設定はありません", noExclSub: "すべての CRS ルールが設定どおりに動作しています。", noSitesFound: "バーチャルホストはありません", noSitesSub: "すべてのリクエストはデフォルトアップストリームに転送されます。", noTestFound: "送信されたリクエストはありません", noTestSub: "プリセットを選択するかリクエストを入力して送信をクリックしてください。", noEventsFilter: "フィルタに一致する監査イベントはありません。時間範囲を変更するかトラフィックを送信してください。", language:'言語',theme:'テーマ',auto:'自動',light:'ライト',dark:'ダーク',console:'管理コンソール',navigation:'メインナビゲーション',monitor:'監視',protection:'保護',tools:'ツール',dashboard:'ダッシュボード',events:'監査イベント',rules:'CRS ルール',custom:'カスタムルール',exclusions:'除外設定',ipLists:'IP リスト',proxy:'リバースプロキシ',test:'テストコンソール',settings:'設定',checking:'確認中…',sites:'サイト',reload:'再読み込み',logout:'ログアウト',collapse:'サイドバーを折りたたむ',expand:'サイドバーを展開',loginTitle:'管理パネルにログイン',loginLead:'インストール時に設定した管理者パスワードを使用してください。',loginHero:'WAF とリバースプロキシを一つのパネルで管理。',loginCopy:'設定ファイルを手動編集せずに、OWASP CRS、除外、カスタムルール、IP リスト、アップストリーム、監査ログを管理できます。',adminPassword:'管理者パスワード',enterPassword:'パスワードを入力',showPassword:'パスワードを表示',signIn:'ログイン',passwordRequired:'パスワードを入力してください。',verifying:'確認中…',defaultPassword:'初期パスワード <strong>admin</strong> が有効です。<span class="mono">.env</span> で <span class="mono">OPENWAF_ADMIN_PASSWORD</span> を設定してください。',loading:'読み込み中…',blocked:'ブロック',detected:'検出',allowed:'許可',dashSubtitle:'WAF の状態、検査トラフィック、最近の脅威の概要。',refresh:'更新',testRequest:'リクエストをテスト',audit24:'監査イベント · 24時間',uniqueIps:'ユニーク IP',passed:'許可',blocked24:'ブロック · 24時間',totalEvents:'全イベント中',detectedOnly:'検出のみ',anomalyHint:'異常スコアはしきい値未満です',disabled:'無効',customShort:'カスタム',eventTrend:'24時間のイベント推移',eventTrendSub:'時間ごとのブロック、検出、許可',allEvents:'全イベント',wafStatus:'WAF ステータス',unavailable:'利用不可',containerName:'コンテナ名',engineMode:'エンジンモード',auditEngine:'監査エンジン',paranoia:'パラノイアレベル',threshold:'しきい値',crsVersion:'CRS バージョン',auditLog:'監査ログ',topRules:'よく発火するルール',last24:'過去24時間',openRules:'ルールを開く',topIps:'上位クライアント IP',basedAudit:'監査イベントに基づく',latestEvents:'最新イベント',clickDetail:'行をクリックして監査ログの詳細を表示',time:'時刻',action:'アクション',request:'リクエスト',status:'状態',rule:'ルール',noEvents:'イベントはありません',noEventsText:'監査ログは空です。WAF にトラフィックを送信してください。',viewAll:'すべて表示',noRule:'発火したルールはありません。',noIp:'クライアント IP データはありません。',defaultWarning:'初期パスワードを使用中です。<span class="mono">OPENWAF_ADMIN_PASSWORD</span> を設定してください。',eventsIn24h:'24時間以内のイベント',validateAndReload:'WAF の検証と再読み込み' },
};

Object.assign(I18N.en, { crsUpdateTitle: 'Update OWASP Core Rule Set', installedVersion: 'Installed version', latestVersion: 'Latest version', upToDate: 'Up to date', updateAvailable: 'Update available', crsLatestToast: 'CRS is already up to date.' });
Object.assign(I18N.id, { crsUpdateTitle: 'Perbarui OWASP Core Rule Set', installedVersion: 'Versi terpasang', latestVersion: 'Versi terbaru', upToDate: 'Sudah terbaru', updateAvailable: 'Pembaruan tersedia', crsLatestToast: 'CRS sudah menggunakan versi terbaru.' });
Object.assign(I18N.zh, { crsUpdateTitle: '更新 OWASP Core Rule Set', installedVersion: '已安装版本', latestVersion: '最新版本', upToDate: '已是最新版本', updateAvailable: '有可用更新', crsLatestToast: 'CRS 已是最新版本。' });
Object.assign(I18N.ar, { crsUpdateTitle: 'تحديث OWASP Core Rule Set', installedVersion: 'الإصدار المثبت', latestVersion: 'أحدث إصدار', upToDate: 'محدّث', updateAvailable: 'يتوفر تحديث', crsLatestToast: 'CRS محدّث بالفعل.' });
Object.assign(I18N.ja, { crsUpdateTitle: 'OWASP Core Rule Set の更新', installedVersion: 'インストール済みバージョン', latestVersion: '最新バージョン', upToDate: '最新です', updateAvailable: '更新があります', crsLatestToast: 'CRS は最新です。' });
Object.assign(I18N.en, { auditRetentionTitle: 'Audit log retention', auditRetentionDesc: 'Delete audit transactions older than the retention period. Checks run hourly and pruning occurs at most once per day.', autoPrune: 'Automatic pruning', enabledOption: 'Enabled', disabledOption: 'Disabled', keepLogsDays: 'Keep logs for (days)', retentionRange: 'Range: 1–3650 days. Default: 30 days.', lastPrune: 'Last prune', lastResult: 'Last result', lastSize: 'Last size', errorLabel: 'Error', removed: 'removed', kept: 'kept', errorPagesTitle: 'Custom error pages', errorPagesDesc: 'Response pages for WAF and upstream errors. HTML is generated locally and remains available when the backend application fails.', statusLabel: 'Status', errorPageLanguage: 'Error-page language', errorLanguageHint: 'Changing this selection fills titles and messages with that language preset.', accentColor: 'Accent color', brandName: 'Brand name', supportText: 'Help text', titleLabel: 'Title', messageLabel: 'Message' });
Object.assign(I18N.id, { auditRetentionTitle: 'Retensi audit log', auditRetentionDesc: 'Hapus transaksi audit yang lebih lama dari masa penyimpanan. Pemeriksaan otomatis berjalan setiap jam dan prune maksimal sekali sehari.', autoPrune: 'Prune otomatis', enabledOption: 'Aktif', disabledOption: 'Nonaktif', keepLogsDays: 'Simpan log selama (hari)', retentionRange: 'Rentang 1–3650 hari. Default 30 hari.', lastPrune: 'Prune terakhir', lastResult: 'Hasil terakhir', lastSize: 'Ukuran terakhir', errorLabel: 'Kesalahan', removed: 'dihapus', kept: 'dipertahankan', errorPagesTitle: 'Halaman error kustom', errorPagesDesc: 'Halaman respons untuk error WAF dan upstream. HTML dibuat lokal dan tetap tersedia saat aplikasi backend gagal.', statusLabel: 'Status', errorPageLanguage: 'Bahasa halaman error', errorLanguageHint: 'Mengganti pilihan akan mengisi judul dan pesan dengan preset bahasa tersebut.', accentColor: 'Warna aksen', brandName: 'Nama brand', supportText: 'Teks bantuan', titleLabel: 'Judul', messageLabel: 'Pesan' });
Object.assign(I18N.zh, { auditRetentionTitle: '审计日志保留', auditRetentionDesc: '删除超过保留期限的审计事务。系统每小时检查一次，每天最多清理一次。', autoPrune: '自动清理', enabledOption: '启用', disabledOption: '禁用', keepLogsDays: '日志保留天数', retentionRange: '范围：1–3650 天。默认：30 天。', lastPrune: '上次清理', lastResult: '上次结果', lastSize: '上次大小', errorLabel: '错误', removed: '已删除', kept: '已保留', errorPagesTitle: '自定义错误页面', errorPagesDesc: '用于 WAF 和上游错误的响应页面。HTML 在本地生成，后端应用故障时仍可用。', statusLabel: '状态', errorPageLanguage: '错误页面语言', errorLanguageHint: '更改此选项将使用对应语言的预设标题和消息。', accentColor: '强调色', brandName: '品牌名称', supportText: '帮助文本', titleLabel: '标题', messageLabel: '消息' });
Object.assign(I18N.ar, { auditRetentionTitle: 'الاحتفاظ بسجل التدقيق', auditRetentionDesc: 'حذف معاملات التدقيق الأقدم من مدة الاحتفاظ. يتم الفحص كل ساعة والتنظيف مرة واحدة يوميًا كحد أقصى.', autoPrune: 'التنظيف التلقائي', enabledOption: 'مفعّل', disabledOption: 'معطّل', keepLogsDays: 'الاحتفاظ بالسجلات (بالأيام)', retentionRange: 'النطاق: 1–3650 يومًا. الافتراضي: 30 يومًا.', lastPrune: 'آخر تنظيف', lastResult: 'آخر نتيجة', lastSize: 'آخر حجم', errorLabel: 'خطأ', removed: 'محذوف', kept: 'محتفظ به', errorPagesTitle: 'صفحات خطأ مخصصة', errorPagesDesc: 'صفحات استجابة لأخطاء WAF والخادم الخلفي. يتم إنشاء HTML محليًا ويظل متاحًا عند تعطل التطبيق الخلفي.', statusLabel: 'الحالة', errorPageLanguage: 'لغة صفحة الخطأ', errorLanguageHint: 'يملأ تغيير هذا الخيار العناوين والرسائل بالإعداد المسبق للغة المحددة.', accentColor: 'لون التمييز', brandName: 'اسم العلامة', supportText: 'نص المساعدة', titleLabel: 'العنوان', messageLabel: 'الرسالة' });
Object.assign(I18N.ja, { auditRetentionTitle: '監査ログの保持', auditRetentionDesc: '保持期間を過ぎた監査トランザクションを削除します。毎時確認し、クリーンアップは1日1回まで実行されます。', autoPrune: '自動クリーンアップ', enabledOption: '有効', disabledOption: '無効', keepLogsDays: 'ログ保持日数', retentionRange: '範囲：1～3650日。既定：30日。', lastPrune: '前回のクリーンアップ', lastResult: '前回の結果', lastSize: '前回のサイズ', errorLabel: 'エラー', removed: '削除', kept: '保持', errorPagesTitle: 'カスタムエラーページ', errorPagesDesc: 'WAF およびアップストリームエラー用の応答ページです。HTML はローカルで生成され、バックエンド障害時も利用できます。', statusLabel: '状態', errorPageLanguage: 'エラーページの言語', errorLanguageHint: '言語を変更すると、その言語のプリセットでタイトルとメッセージが入力されます。', accentColor: 'アクセントカラー', brandName: 'ブランド名', supportText: 'ヘルプテキスト', titleLabel: 'タイトル', messageLabel: 'メッセージ' });
Object.assign(I18N.en, { never: 'never' }); Object.assign(I18N.id, { never: 'belum pernah' }); Object.assign(I18N.zh, { never: '从未' }); Object.assign(I18N.ar, { never: 'أبدًا' }); Object.assign(I18N.ja, { never: 'なし' });
Object.assign(I18N.en, { errorPagesSaved: 'Custom error pages were saved and applied.' }); Object.assign(I18N.id, { errorPagesSaved: 'Halaman error kustom disimpan dan diterapkan.' }); Object.assign(I18N.zh, { errorPagesSaved: '自定义错误页面已保存并应用。' }); Object.assign(I18N.ar, { errorPagesSaved: 'تم حفظ صفحات الخطأ المخصصة وتطبيقها.' }); Object.assign(I18N.ja, { errorPagesSaved: 'カスタムエラーページを保存して適用しました。' });
Object.assign(I18N.en, { paranoiaDesc: 'A higher paranoia level adds more detection rules, but also increases the potential for false positives.', plBasic: 'Basic, low false-positive rate', plBalanced: 'Balanced (common)', plStrict: 'Strict', plVeryStrict: 'Very strict', threatDesc: 'Combine community blocklists into ModSecurity rules. The local allowlist always takes precedence.', protectionStatus: 'Protection status', blocklistSources: 'Blocklist sources', normalRequest: 'Normal request', additionalHeaders: 'Additional headers', upstreamHint: 'Scheme + host + port only, without a path. Example:', routingSecurity: 'Routing & security', protectedSites: 'Protected sites', hostnameRouting: 'Hostname-based routing', allowlistHint: 'Always allowed — takes precedence over the blocklist.', rulesDetected: 'rules detected', interrupted: 'Interrupted', triggeredRules: 'Triggered rules', noTriggeredRules: 'No rules were triggered for this event.', yes: 'yes', no: 'no' });
Object.assign(I18N.id, { paranoiaDesc: 'Paranoia lebih tinggi menambah rule deteksi, tetapi juga potensi false positive.', plBasic: 'Dasar, false positive rendah', plBalanced: 'Seimbang (umum)', plStrict: 'Ketat', plVeryStrict: 'Sangat ketat', threatDesc: 'Gabungkan blocklist komunitas menjadi rule ModSecurity. Allowlist lokal tetap menang.', protectionStatus: 'Status proteksi', blocklistSources: 'Sumber blocklist', normalRequest: 'Request normal', additionalHeaders: 'Header tambahan', upstreamHint: 'Hanya skema + host + port, tanpa path. Contoh:', routingSecurity: 'Routing & keamanan', protectedSites: 'Situs diproteksi', hostnameRouting: 'Routing berdasarkan hostname', allowlistHint: 'Selalu diizinkan — menang atas blocklist.', rulesDetected: 'rule terdeteksi', interrupted: 'Interrupted', triggeredRules: 'Rule yang terpicu', noTriggeredRules: 'Tidak ada rule yang terpicu pada event ini.', yes: 'ya', no: 'tidak' });
Object.assign(I18N.en, { exclusionRecommended: 'Recommended for false positives.', exclusionVsAllow: 'An exclusion disables only selected CRS rule IDs for a path or host. A custom allow rule can bypass all subsequent WAF checks, so it should not replace exclusions.' });
Object.assign(I18N.id, { exclusionRecommended: 'Disarankan untuk false positive.', exclusionVsAllow: 'Exclusion hanya menonaktifkan rule ID CRS tertentu pada path atau host. Custom rule allow dapat melewati semua pemeriksaan WAF berikutnya, sehingga tidak menggantikan fungsi exclusion.' });
Object.assign(I18N.en, { allowIp: 'Allow IP', blockIp: 'Block IP', allowIpTitle: 'Allow this client IP?', blockIpTitle: 'Block this client IP?', allowIpConfirm: 'This IP will bypass WAF inspection for all sites. Use this only for a trusted client:', blockIpConfirm: 'This IP will be blocked on all protected sites:', ipActionApplied: 'The IP list was updated and the WAF was reloaded.' });
Object.assign(I18N.id, { allowIp: 'Izinkan IP', blockIp: 'Blokir IP', allowIpTitle: 'Izinkan client IP ini?', blockIpTitle: 'Blokir client IP ini?', allowIpConfirm: 'IP ini akan melewati pemeriksaan WAF di semua situs. Gunakan hanya untuk client tepercaya:', blockIpConfirm: 'IP ini akan diblokir di semua situs yang dilindungi:', ipActionApplied: 'IP list diperbarui dan WAF berhasil di-reload.' });
Object.assign(I18N.zh, { allowIp: '允许 IP', blockIp: '封禁 IP', allowIpTitle: '允许此客户端 IP？', blockIpTitle: '封禁此客户端 IP？', allowIpConfirm: '此 IP 将绕过所有站点的 WAF 检查。请仅用于可信客户端：', blockIpConfirm: '此 IP 将在所有受保护站点上被封禁：', ipActionApplied: 'IP 列表已更新，WAF 已重新加载。' });
Object.assign(I18N.ar, { allowIp: 'السماح لعنوان IP', blockIp: 'حظر عنوان IP', allowIpTitle: 'السماح لعنوان IP هذا؟', blockIpTitle: 'حظر عنوان IP هذا؟', allowIpConfirm: 'سيتجاوز هذا العنوان فحص WAF لجميع المواقع. استخدمه فقط لعميل موثوق:', blockIpConfirm: 'سيتم حظر هذا العنوان في جميع المواقع المحمية:', ipActionApplied: 'تم تحديث قائمة IP وإعادة تحميل WAF.' });
Object.assign(I18N.ja, { allowIp: 'IP を許可', blockIp: 'IP をブロック', allowIpTitle: 'このクライアント IP を許可しますか？', blockIpTitle: 'このクライアント IP をブロックしますか？', allowIpConfirm: 'この IP はすべてのサイトで WAF 検査を回避します。信頼できるクライアントにのみ使用してください：', blockIpConfirm: 'この IP は保護対象のすべてのサイトでブロックされます：', ipActionApplied: 'IP リストを更新し、WAF を再読み込みしました。' });
Object.assign(I18N.en, { allowPath: 'Allow path', blockPath: 'Block path', allowPathTitle: 'Allow this exact host and path?', blockPathTitle: 'Block this exact host and path?', allowPathConfirm: 'Only the triggered CRS rule IDs will be excluded for this exact host and path:', blockPathConfirm: 'Requests to this exact host and path will be denied:', pathActionApplied: 'The host/path rule was applied and the WAF was reloaded.' });
Object.assign(I18N.id, { allowPath: 'Izinkan path', blockPath: 'Blokir path', allowPathTitle: 'Izinkan host dan path ini?', blockPathTitle: 'Blokir host dan path ini?', allowPathConfirm: 'Hanya rule ID CRS yang terpicu yang dikecualikan untuk host dan path persis ini:', blockPathConfirm: 'Request ke host dan path persis ini akan ditolak:', pathActionApplied: 'Rule host/path diterapkan dan WAF berhasil di-reload.' });
Object.assign(I18N.zh, { allowPath: '允许路径', blockPath: '封禁路径', allowPathTitle: '允许此精确主机和路径？', blockPathTitle: '封禁此精确主机和路径？', allowPathConfirm: '仅对此精确主机和路径排除已触发的 CRS 规则 ID：', blockPathConfirm: '对此精确主机和路径的请求将被拒绝：', pathActionApplied: '主机/路径规则已应用，WAF 已重新加载。' });
Object.assign(I18N.ar, { allowPath: 'السماح بالمسار', blockPath: 'حظر المسار', allowPathTitle: 'السماح لهذا المضيف والمسار بالضبط؟', blockPathTitle: 'حظر هذا المضيف والمسار بالضبط؟', allowPathConfirm: 'سيتم استثناء معرفات قواعد CRS المشغلة فقط لهذا المضيف والمسار:', blockPathConfirm: 'سيتم رفض الطلبات إلى هذا المضيف والمسار بالضبط:', pathActionApplied: 'تم تطبيق قاعدة المضيف/المسار وإعادة تحميل WAF.' });
Object.assign(I18N.ja, { allowPath: 'パスを許可', blockPath: 'パスをブロック', allowPathTitle: 'このホストとパスを許可しますか？', blockPathTitle: 'このホストとパスをブロックしますか？', allowPathConfirm: 'この正確なホストとパスについて、発火した CRS ルール ID のみ除外します：', blockPathConfirm: 'この正確なホストとパスへのリクエストを拒否します：', pathActionApplied: 'ホスト/パスルールを適用し、WAF を再読み込みしました。' });
Object.assign(I18N.en, { attackMap: 'Attack origin map', attackMapSub: 'Blocked or detected events · 24 hours', noGeoAttacks: 'No public attack source has been geolocated yet.', localTraffic: 'local/private events', geoPrivacy: 'Only public attack IPs are sent to the GeoIP provider.', languageSaved: 'Language settings were saved.' });
Object.assign(I18N.id, { attackMap: 'Peta sumber serangan', attackMapSub: 'Event diblokir atau terdeteksi · 24 jam', noGeoAttacks: 'Belum ada sumber serangan publik yang dapat dipetakan.', localTraffic: 'event lokal/private', geoPrivacy: 'Hanya IP publik dari event serangan yang dikirim ke penyedia GeoIP.', languageSaved: 'Pengaturan bahasa berhasil disimpan.' });
Object.assign(I18N.zh, { attackMap: '攻击来源地图', attackMapSub: '已拦截或检测事件 · 24 小时', noGeoAttacks: '尚无可定位的公共攻击来源。', localTraffic: '本地/私有事件', geoPrivacy: '仅向 GeoIP 提供商发送攻击事件中的公共 IP。', languageSaved: '语言设置已保存。' });
Object.assign(I18N.ar, { attackMap: 'خريطة مصادر الهجوم', attackMapSub: 'الأحداث المحظورة أو المكتشفة · 24 ساعة', noGeoAttacks: 'لا توجد مصادر هجوم عامة محددة الموقع بعد.', localTraffic: 'أحداث محلية/خاصة', geoPrivacy: 'يتم إرسال عناوين IP العامة للهجمات فقط إلى مزود GeoIP.', languageSaved: 'تم حفظ إعدادات اللغة.' });
Object.assign(I18N.ja, { attackMap: '攻撃元マップ', attackMapSub: 'ブロックまたは検出イベント · 24時間', noGeoAttacks: '位置を特定できる公開攻撃元はまだありません。', localTraffic: 'ローカル/プライベートイベント', geoPrivacy: '攻撃イベントの公開 IP のみ GeoIP プロバイダーへ送信します。', languageSaved: '言語設定を保存しました。' });
Object.assign(I18N.en, { lastChecked: 'Last checked', cachedResult: 'cached result', checkFailedCached: 'Latest check failed; showing the saved result.' });
Object.assign(I18N.id, { lastChecked: 'Terakhir diperiksa', cachedResult: 'hasil tersimpan', checkFailedCached: 'Pemeriksaan terbaru gagal; menampilkan hasil tersimpan.' });
Object.assign(I18N.zh, { lastChecked: '上次检查', cachedResult: '已保存结果', checkFailedCached: '最新检查失败；正在显示已保存的结果。' });
Object.assign(I18N.ar, { lastChecked: 'آخر فحص', cachedResult: 'نتيجة محفوظة', checkFailedCached: 'فشل آخر فحص؛ يتم عرض النتيجة المحفوظة.' });
Object.assign(I18N.ja, { lastChecked: '最終確認', cachedResult: '保存済み結果', checkFailedCached: '最新の確認に失敗したため、保存済みの結果を表示しています。' });
Object.assign(I18N.en, { fallbackBehavior: 'Unmatched request behavior', return404: 'Return 404 (recommended)', forwardDefault: 'Forward to default upstream', fallback404Hint: 'Unknown hosts are rejected locally and are never sent to a backend.', fallbackForwardHint: 'Unknown hosts are forwarded to the URL below.' });
Object.assign(I18N.id, { fallbackBehavior: 'Perilaku request yang tidak cocok', return404: 'Kembalikan 404 (disarankan)', forwardDefault: 'Teruskan ke upstream default', fallback404Hint: 'Host yang tidak dikenal ditolak secara lokal dan tidak dikirim ke backend.', fallbackForwardHint: 'Host yang tidak dikenal diteruskan ke URL di bawah.' });
Object.assign(I18N.zh, { fallbackBehavior: '未匹配请求的处理方式', return404: '返回 404（推荐）', forwardDefault: '转发到默认上游', fallback404Hint: '未知主机将在本地被拒绝，不会发送到后端。', fallbackForwardHint: '未知主机将被转发到以下 URL。' });
Object.assign(I18N.ar, { fallbackBehavior: 'سلوك الطلبات غير المتطابقة', return404: 'إرجاع 404 (موصى به)', forwardDefault: 'إعادة التوجيه إلى الخادم الافتراضي', fallback404Hint: 'يتم رفض المضيفين غير المعروفين محليًا ولا يتم إرسالهم إلى الخلفية.', fallbackForwardHint: 'يتم توجيه المضيفين غير المعروفين إلى العنوان أدناه.' });
Object.assign(I18N.ja, { fallbackBehavior: '一致しないリクエストの動作', return404: '404 を返す（推奨）', forwardDefault: 'デフォルトアップストリームへ転送', fallback404Hint: '不明なホストはローカルで拒否され、バックエンドへ送信されません。', fallbackForwardHint: '不明なホストは以下の URL へ転送されます。' });

Object.assign(I18N.en, { copied:'Copied to clipboard.',copyFailed:'Copy failed. Please copy it manually.',genericError:'An error occurred.',validationFailed:'Configuration validation failed',changesCancelled:'Changes were cancelled. Output from nginx -t / ModSecurity:',saving:'Saving…',pageLoadFailed:'Failed to load the page.',timelineEmpty:'No timeline data yet.',requiredPattern:'Pattern is required.',requiredIp:'IP address is required.',requiredHostname:'At least one hostname is required.',requiredUpstream:'Upstream is required.',customDeleted:'Custom rule deleted.',customCreated:'Custom rule created.',customUpdated:'Custom rule updated.',exclusionDeleted:'Exclusion deleted.',exclusionCreated:'Exclusion created.',exclusionUpdated:'Exclusion updated.',ipAdded:'IP entry added.',ipDeleted:'IP entry deleted.',siteDeleted:'Virtual host deleted.',siteCreated:'Site created.',siteUpdated:'Site updated.',fallbackApplied:'HTTP 404 fallback applied.',upstreamSaved:'Default upstream saved.',settingsReloaded:'Settings saved and WAF reloaded.',settingsReloadSkipped:'Settings saved; WAF reload was skipped.',rateApplied:'Rate limit saved and applied.',rateReloadSkipped:'Rate limit saved; reload was skipped.',threatSaved:'Threat-intelligence configuration saved.',retentionSaved:'Audit-log retention policy saved.',reloadUnavailable:'WAF reload skipped (Docker is unavailable).'});
Object.assign(I18N.id, { copied:'Disalin ke clipboard.',copyFailed:'Gagal menyalin. Silakan salin manual.',genericError:'Terjadi kesalahan.',validationFailed:'Validasi konfigurasi gagal',changesCancelled:'Perubahan dibatalkan. Output dari nginx -t / ModSecurity:',saving:'Menyimpan…',pageLoadFailed:'Gagal memuat halaman.',timelineEmpty:'Belum ada data timeline.',requiredPattern:'Pattern wajib diisi.',requiredIp:'Alamat IP wajib diisi.',requiredHostname:'Minimal satu hostname wajib diisi.',requiredUpstream:'Upstream wajib diisi.',customDeleted:'Custom rule dihapus.',customCreated:'Custom rule dibuat.',customUpdated:'Custom rule diperbarui.',exclusionDeleted:'Exclusion dihapus.',exclusionCreated:'Exclusion dibuat.',exclusionUpdated:'Exclusion diperbarui.',ipAdded:'Entri IP ditambahkan.',ipDeleted:'Entri IP dihapus.',siteDeleted:'Virtual host dihapus.',siteCreated:'Situs dibuat.',siteUpdated:'Situs diperbarui.',fallbackApplied:'Fallback HTTP 404 diterapkan.',upstreamSaved:'Upstream default disimpan.',settingsReloaded:'Pengaturan disimpan dan WAF di-reload.',settingsReloadSkipped:'Pengaturan disimpan; reload WAF dilewati.',rateApplied:'Rate limit disimpan dan diterapkan.',rateReloadSkipped:'Rate limit disimpan; reload dilewati.',threatSaved:'Konfigurasi threat intelligence disimpan.',retentionSaved:'Kebijakan retensi audit log disimpan.',reloadUnavailable:'Reload WAF dilewati (Docker tidak tersedia).'});
Object.assign(I18N.zh, { copied:'已复制到剪贴板。',copyFailed:'复制失败，请手动复制。',genericError:'发生错误。',validationFailed:'配置验证失败',changesCancelled:'更改已取消。nginx -t / ModSecurity 输出：',saving:'保存中…',pageLoadFailed:'页面加载失败。',timelineEmpty:'暂无时间线数据。',requiredPattern:'必须填写模式。',requiredIp:'必须填写 IP 地址。',requiredHostname:'至少需要一个主机名。',requiredUpstream:'必须填写上游地址。'});
Object.assign(I18N.ar, { copied:'تم النسخ إلى الحافظة.',copyFailed:'فشل النسخ. يرجى النسخ يدويًا.',genericError:'حدث خطأ.',validationFailed:'فشل التحقق من التكوين',changesCancelled:'أُلغيت التغييرات. مخرجات nginx -t / ModSecurity:',saving:'جارٍ الحفظ…',pageLoadFailed:'فشل تحميل الصفحة.',timelineEmpty:'لا توجد بيانات للمخطط الزمني بعد.',requiredPattern:'النمط مطلوب.',requiredIp:'عنوان IP مطلوب.',requiredHostname:'يلزم اسم مضيف واحد على الأقل.',requiredUpstream:'عنوان الخادم الخلفي مطلوب.'});
Object.assign(I18N.ja, { copied:'クリップボードにコピーしました。',copyFailed:'コピーできませんでした。手動でコピーしてください。',genericError:'エラーが発生しました。',validationFailed:'設定の検証に失敗しました',changesCancelled:'変更を取り消しました。nginx -t / ModSecurity の出力：',saving:'保存中…',pageLoadFailed:'ページを読み込めませんでした。',timelineEmpty:'タイムラインデータはまだありません。',requiredPattern:'パターンは必須です。',requiredIp:'IP アドレスは必須です。',requiredHostname:'ホスト名を1つ以上指定してください。',requiredUpstream:'アップストリームは必須です。'});
Object.assign(I18N.en, { chartTotal:'Total', chartEvents:'events', chartAria:'Hourly security events chart' });
Object.assign(I18N.id, { chartTotal:'Total', chartEvents:'event', chartAria:'Grafik event keamanan per jam' });
Object.assign(I18N.zh, { chartTotal:'总计', chartEvents:'事件', chartAria:'每小时安全事件图表' });
Object.assign(I18N.ar, { chartTotal:'الإجمالي', chartEvents:'أحداث', chartAria:'مخطط أحداث الأمان لكل ساعة' });
Object.assign(I18N.ja, { chartTotal:'合計', chartEvents:'イベント', chartAria:'時間別セキュリティイベントチャート' });
Object.assign(I18N.en, { enableRule:'Enable rule',disableRule:'Disable rule',ruleEnabled:'Rule enabled.',ruleDisabled:'Rule disabled.',ruleDefinition:'Rule definition',globalExclusion:'Global exclusion',disabledByExclusion:'Disabled by a global exclusion. Remove the exclusion on the Exclusions page.',disabledByGlobalExclusion:'Disabled by global exclusion',viewCode:'View code',copy:'Copy',enabledCount:'enabled',disabledCount:'disabled' });
Object.assign(I18N.id, { enableRule:'Aktifkan rule',disableRule:'Nonaktifkan rule',ruleEnabled:'Rule diaktifkan.',ruleDisabled:'Rule dinonaktifkan.',ruleDefinition:'Definisi rule',globalExclusion:'Exclusion global',disabledByExclusion:'Nonaktif karena exclusion global. Hapus exclusion di halaman Exclusions.',disabledByGlobalExclusion:'Dinonaktifkan oleh exclusion global',viewCode:'Lihat kode',copy:'Salin',enabledCount:'aktif',disabledCount:'nonaktif' });
Object.assign(I18N.zh, { enableRule:'启用规则',disableRule:'禁用规则',ruleEnabled:'规则已启用。',ruleDisabled:'规则已禁用。',ruleDefinition:'规则定义',globalExclusion:'全局排除',disabledByExclusion:'已被全局排除禁用。请在排除项页面移除该排除项。',disabledByGlobalExclusion:'已被全局排除禁用',viewCode:'查看代码',copy:'复制',enabledCount:'已启用',disabledCount:'已禁用' });
Object.assign(I18N.ar, { enableRule:'تفعيل القاعدة',disableRule:'تعطيل القاعدة',ruleEnabled:'تم تفعيل القاعدة.',ruleDisabled:'تم تعطيل القاعدة.',ruleDefinition:'تعريف القاعدة',globalExclusion:'استثناء عام',disabledByExclusion:'معطلة بسبب استثناء عام. احذف الاستثناء من صفحة الاستثناءات.',disabledByGlobalExclusion:'معطلة بواسطة استثناء عام',viewCode:'عرض الشفرة',copy:'نسخ',enabledCount:'مفعّلة',disabledCount:'معطلة' });
Object.assign(I18N.ja, { enableRule:'ルールを有効化',disableRule:'ルールを無効化',ruleEnabled:'ルールを有効にしました。',ruleDisabled:'ルールを無効にしました。',ruleDefinition:'ルール定義',globalExclusion:'グローバル除外',disabledByExclusion:'グローバル除外により無効です。除外設定ページで削除してください。',disabledByGlobalExclusion:'グローバル除外により無効',viewCode:'コードを表示',copy:'コピー',enabledCount:'有効',disabledCount:'無効' });
Object.assign(I18N.en, { patternExample:'Example: ^/admin or (?:select|union).*from', newCustomTitle:'New custom rule',editCustomTitle:'Edit custom rule',ruleName:'Rule name',ruleNameExample:'Example: Block public access to /admin',fieldVariable:'Field / variable',operator:'Operator',patternHint:'Do not include opening or closing quotes. Escape special regex characters when needed.',actionLabel:'Action',denyAction:'deny (block)',passAction:'pass (log only)',allowAction:'allow (skip subsequent checks)',allowWarning:'Use allow only for highly specific, trusted conditions because matching requests can bypass subsequent WAF rules.',logMessage:'Log message',logMessageHint:'Message shown in the audit log',rawRuleHint:'Must contain id:9000000–9999999 and phase:1–5. Include directives are not allowed.',optionalNote:'Note (optional)',noteHint:'Reason / change ticket',ruleAppliedHint:'The rule is applied immediately after saving.',preview:'Preview',saveChanges:'Save changes',createRule:'Create rule',rawRuleEmpty:'Raw rule cannot be empty.',startRawRule:'# Start writing a raw rule…',generatedRule:'Generated rule',customEnabled:'Custom rule enabled.',customDisabled:'Custom rule disabled.',deleteCustomTitle:'Delete custom rule?',deleteCustomConfirm:'The custom rule will be deleted and the WAF reloaded:',deleteRule:'Delete rule',opContains:'Contains (@contains)',opBegins:'Begins with (@beginsWith)',opEnds:'Ends with (@endsWith)',opEquals:'Equals (@eq)',opKeywords:'Keywords (@pm)',opGreater:'Greater than (@gt)',opLess:'Less than (@lt)' });
Object.assign(I18N.id, { newCustomTitle:'Custom rule baru',editCustomTitle:'Edit custom rule',ruleName:'Nama rule',ruleNameExample:'Contoh: Blokir akses publik ke /admin',fieldVariable:'Field / variabel',operator:'Operator',patternHint:'Tanpa tanda kutip pembuka/penutup. Escape karakter khusus regex bila perlu.',actionLabel:'Aksi',denyAction:'deny (blokir)',passAction:'pass (log saja)',allowAction:'allow (lewati pemeriksaan berikutnya)',allowWarning:'Gunakan allow hanya untuk kondisi yang sangat spesifik dan terpercaya karena request yang cocok dapat melewati rule WAF berikutnya.',logMessage:'Pesan log',logMessageHint:'Pesan yang muncul di audit log',rawRuleHint:'Harus memuat id:9000000–9999999 dan phase:1–5. Directive Include tidak diizinkan.',optionalNote:'Catatan (opsional)',noteHint:'Alasan / tiket perubahan',ruleAppliedHint:'Rule langsung diterapkan setelah disimpan.',preview:'Pratinjau',saveChanges:'Simpan perubahan',createRule:'Buat rule',rawRuleEmpty:'Raw rule masih kosong.',startRawRule:'# Mulai tulis raw rule…',generatedRule:'Rule yang dihasilkan',customEnabled:'Custom rule diaktifkan.',customDisabled:'Custom rule dinonaktifkan.',deleteCustomTitle:'Hapus custom rule?',deleteCustomConfirm:'Custom rule akan dihapus dan WAF di-reload:',deleteRule:'Hapus rule',opContains:'Mengandung (@contains)',opBegins:'Diawali (@beginsWith)',opEnds:'Diakhiri (@endsWith)',opEquals:'Sama dengan (@eq)',opKeywords:'Kata kunci (@pm)',opGreater:'Lebih besar (@gt)',opLess:'Lebih kecil (@lt)' });
Object.assign(I18N.zh, { newCustomTitle:'新建自定义规则',editCustomTitle:'编辑自定义规则',ruleName:'规则名称',ruleNameExample:'示例：阻止公开访问 /admin',fieldVariable:'字段 / 变量',operator:'运算符',patternHint:'请勿包含首尾引号，必要时转义正则表达式特殊字符。',actionLabel:'操作',denyAction:'deny（阻止）',passAction:'pass（仅记录）',allowAction:'allow（跳过后续检查）',allowWarning:'仅对非常具体且可信的条件使用 allow，因为匹配的请求可能绕过后续 WAF 规则。',logMessage:'日志消息',logMessageHint:'审计日志中显示的消息',rawRuleHint:'必须包含 id:9000000–9999999 和 phase:1–5。不允许 Include 指令。',optionalNote:'备注（可选）',noteHint:'原因 / 变更工单',ruleAppliedHint:'保存后立即应用规则。',preview:'预览',saveChanges:'保存更改',createRule:'创建规则',rawRuleEmpty:'原始规则不能为空。',startRawRule:'# 开始编写原始规则…',generatedRule:'生成的规则',customEnabled:'自定义规则已启用。',customDisabled:'自定义规则已禁用。',deleteCustomTitle:'删除自定义规则？',deleteCustomConfirm:'自定义规则将被删除并重载 WAF：',deleteRule:'删除规则',opContains:'包含 (@contains)',opBegins:'开头为 (@beginsWith)',opEnds:'结尾为 (@endsWith)',opEquals:'等于 (@eq)',opKeywords:'关键字 (@pm)',opGreater:'大于 (@gt)',opLess:'小于 (@lt)' });
Object.assign(I18N.ar, { newCustomTitle:'قاعدة مخصصة جديدة',editCustomTitle:'تعديل قاعدة مخصصة',ruleName:'اسم القاعدة',ruleNameExample:'مثال: حظر الوصول العام إلى /admin',fieldVariable:'الحقل / المتغير',operator:'المعامل',patternHint:'لا تضع علامات اقتباس في البداية أو النهاية، وقم بتهريب رموز التعبير النمطي عند الحاجة.',actionLabel:'الإجراء',denyAction:'deny (حظر)',passAction:'pass (تسجيل فقط)',allowAction:'allow (تجاوز الفحوص اللاحقة)',allowWarning:'استخدم allow فقط لشروط محددة وموثوقة جدًا لأن الطلب المطابق قد يتجاوز قواعد WAF اللاحقة.',logMessage:'رسالة السجل',logMessageHint:'الرسالة الظاهرة في سجل التدقيق',rawRuleHint:'يجب أن تحتوي على id:9000000–9999999 و phase:1–5. توجيهات Include غير مسموحة.',optionalNote:'ملاحظة (اختياري)',noteHint:'السبب / تذكرة التغيير',ruleAppliedHint:'تُطبق القاعدة فور الحفظ.',preview:'معاينة',saveChanges:'حفظ التغييرات',createRule:'إنشاء القاعدة',rawRuleEmpty:'لا يمكن أن تكون القاعدة الخام فارغة.',startRawRule:'# ابدأ كتابة القاعدة الخام…',generatedRule:'القاعدة المولدة',customEnabled:'تم تفعيل القاعدة المخصصة.',customDisabled:'تم تعطيل القاعدة المخصصة.',deleteCustomTitle:'حذف القاعدة المخصصة؟',deleteCustomConfirm:'ستُحذف القاعدة المخصصة ويعاد تحميل WAF:',deleteRule:'حذف القاعدة',opContains:'يحتوي (@contains)',opBegins:'يبدأ بـ (@beginsWith)',opEnds:'ينتهي بـ (@endsWith)',opEquals:'يساوي (@eq)',opKeywords:'كلمات مفتاحية (@pm)',opGreater:'أكبر من (@gt)',opLess:'أصغر من (@lt)' });
Object.assign(I18N.ja, { newCustomTitle:'新しいカスタムルール',editCustomTitle:'カスタムルールを編集',ruleName:'ルール名',ruleNameExample:'例：/admin への公開アクセスをブロック',fieldVariable:'フィールド / 変数',operator:'演算子',patternHint:'先頭と末尾の引用符は不要です。必要に応じて正規表現の特殊文字をエスケープしてください。',actionLabel:'アクション',denyAction:'deny（ブロック）',passAction:'pass（ログのみ）',allowAction:'allow（後続検査をスキップ）',allowWarning:'一致したリクエストが後続の WAF ルールを回避するため、allow は非常に限定的で信頼できる条件にのみ使用してください。',logMessage:'ログメッセージ',logMessageHint:'監査ログに表示するメッセージ',rawRuleHint:'id:9000000–9999999 と phase:1–5 が必要です。Include ディレクティブは使用できません。',optionalNote:'備考（任意）',noteHint:'理由 / 変更チケット',ruleAppliedHint:'保存後すぐにルールが適用されます。',preview:'プレビュー',saveChanges:'変更を保存',createRule:'ルールを作成',rawRuleEmpty:'Raw ルールを入力してください。',startRawRule:'# Raw ルールを入力…',generatedRule:'生成されたルール',customEnabled:'カスタムルールを有効にしました。',customDisabled:'カスタムルールを無効にしました。',deleteCustomTitle:'カスタムルールを削除しますか？',deleteCustomConfirm:'カスタムルールを削除して WAF を再読み込みします：',deleteRule:'ルールを削除',opContains:'含む (@contains)',opBegins:'先頭一致 (@beginsWith)',opEnds:'末尾一致 (@endsWith)',opEquals:'等しい (@eq)',opKeywords:'キーワード (@pm)',opGreater:'より大きい (@gt)',opLess:'より小さい (@lt)' });
Object.assign(I18N.id, { patternExample:'Contoh: ^/admin atau (?:select|union).*from' });
Object.assign(I18N.zh, { patternExample:'示例：^/admin 或 (?:select|union).*from' });
Object.assign(I18N.ar, { patternExample:'مثال: ^/admin أو (?:select|union).*from' });
Object.assign(I18N.ja, { patternExample:'例：^/admin または (?:select|union).*from' });

const preferences = {
  language: LOCALES[localStorage.getItem('openwaf.language')] ? localStorage.getItem('openwaf.language') : 'en',
  theme: ['auto', 'light', 'dark'].includes(localStorage.getItem('openwaf.theme')) ? localStorage.getItem('openwaf.theme') : 'auto',
};

const ERROR_PAGE_PRESETS = {
  en: { support: 'If the problem continues, contact the system administrator.', pages: {
    400:['Bad Request','The request could not be processed because its format is invalid.'], 403:['Forbidden','The request was blocked by the AsekWAF security policy.'], 404:['Not Found','The requested page or resource could not be found.'], 429:['Too Many Requests','Too many requests were received. Please try again later.'], 500:['Internal Server Error','An internal error occurred while processing the request.'], 502:['Bad Gateway','AsekWAF received an invalid response from the upstream application.'], 503:['Service Unavailable','The service is currently unavailable. Please try again later.'], 504:['Gateway Timeout','The upstream application did not respond within the allowed time.'] } },
  id: { support: 'Jika masalah berlanjut, hubungi administrator sistem.', pages: {
    400:['Permintaan Tidak Valid','Permintaan tidak dapat diproses karena formatnya tidak valid.'], 403:['Akses Ditolak','Permintaan ditolak oleh kebijakan keamanan AsekWAF.'], 404:['Tidak Ditemukan','Halaman atau sumber daya yang Anda cari tidak ditemukan.'], 429:['Terlalu Banyak Permintaan','Terlalu banyak permintaan. Silakan coba kembali nanti.'], 500:['Kesalahan Internal Server','Terjadi kesalahan internal saat memproses permintaan.'], 502:['Gateway Tidak Valid','AsekWAF tidak menerima respons yang valid dari aplikasi upstream.'], 503:['Layanan Tidak Tersedia','Layanan sedang tidak tersedia. Silakan coba kembali nanti.'], 504:['Waktu Gateway Habis','Aplikasi upstream tidak merespons dalam batas waktu.'] } },
  zh: { support: '如果问题持续存在，请联系系统管理员。', pages: {
    400:['错误请求','请求格式无效，无法处理。'], 403:['禁止访问','请求已被 AsekWAF 安全策略拦截。'], 404:['未找到','找不到请求的页面或资源。'], 429:['请求过多','请求次数过多，请稍后重试。'], 500:['服务器内部错误','处理请求时发生内部错误。'], 502:['网关错误','AsekWAF 从上游应用收到了无效响应。'], 503:['服务不可用','服务当前不可用，请稍后重试。'], 504:['网关超时','上游应用未能在允许时间内响应。'] } },
  ar: { support: 'إذا استمرت المشكلة، فاتصل بمسؤول النظام.', pages: {
    400:['طلب غير صالح','تعذرت معالجة الطلب لأن تنسيقه غير صالح.'], 403:['ممنوع','تم حظر الطلب بواسطة سياسة أمان AsekWAF.'], 404:['غير موجود','تعذر العثور على الصفحة أو المورد المطلوب.'], 429:['طلبات كثيرة جدًا','تم استلام عدد كبير جدًا من الطلبات. حاول مرة أخرى لاحقًا.'], 500:['خطأ داخلي في الخادم','حدث خطأ داخلي أثناء معالجة الطلب.'], 502:['بوابة غير صالحة','تلقى AsekWAF استجابة غير صالحة من التطبيق الخلفي.'], 503:['الخدمة غير متاحة','الخدمة غير متاحة حاليًا. حاول مرة أخرى لاحقًا.'], 504:['انتهت مهلة البوابة','لم يستجب التطبيق الخلفي خلال الوقت المسموح.'] } },
  ja: { support: '問題が続く場合は、システム管理者にお問い合わせください。', pages: {
    400:['不正なリクエスト','リクエストの形式が無効なため処理できませんでした。'], 403:['アクセス禁止','リクエストは AsekWAF のセキュリティポリシーによってブロックされました。'], 404:['見つかりません','要求されたページまたはリソースが見つかりません。'], 429:['リクエストが多すぎます','リクエストが多すぎます。しばらくしてから再試行してください。'], 500:['サーバー内部エラー','リクエストの処理中に内部エラーが発生しました。'], 502:['不正なゲートウェイ','AsekWAF はアップストリームアプリケーションから無効な応答を受信しました。'], 503:['サービス利用不可','サービスは現在利用できません。しばらくしてから再試行してください。'], 504:['ゲートウェイタイムアウト','アップストリームアプリケーションが制限時間内に応答しませんでした。'] } },
};
const t = (key) => I18N[preferences.language]?.[key] || I18N.en[key] || key;
const currentLocale = () => LOCALES[preferences.language] || LOCALES.en;

const LEGACY_EN = {
  '1 jam terakhir': 'Last hour', '6 jam terakhir': 'Last 6 hours', '24 jam terakhir': 'Last 24 hours', '7 hari terakhir': 'Last 7 days',
  'Nonaktif': 'Disabled', 'Aktif': 'Enabled', 'belum pernah': 'never', 'Entri aktif': 'Active entries', 'Sinkronisasi terakhir': 'Last synchronization', 'Prune terakhir': 'Last prune',
  'Metode & konten yang diizinkan': 'Allowed methods & content', 'Pisahkan dengan spasi.': 'Separate values with spaces.', 'Tidak boleh lebih rendah dari blocking PL.': 'Must not be lower than the blocking PL.',
  'Saat ini 12.5 MB.': 'Currently 12.5 MB.', 'Saat ini 1 MB. 0 = tanpa batas.': 'Currently 1 MB. 0 = unlimited.',
  'Bahasa antarmuka dan preset halaman error dikelola terpusat dari pengaturan ini.': 'The interface language and error-page presets are managed centrally here.',
  'Berlaku untuk navigasi, halaman admin, format tanggal, dan halaman error. Arabic otomatis menggunakan RTL.': 'Applies to navigation, admin pages, date formatting, and error pages. Arabic automatically uses RTL.',
  'Mode blocking menentukan apakah request yang melewati threshold diblokir atau hanya dicatat.': 'Blocking mode determines whether requests exceeding the threshold are blocked or only logged.',
  'RelevantOnly mencatat request yang memicu rule (disarankan).': 'RelevantOnly logs requests that trigger a rule (recommended).',
  'Batasi method HTTP dan content type yang diterima aplikasi Anda.': 'Restrict the HTTP methods and content types accepted by your application.',
  'Format CRS: setiap ekstensi diapit spasi dan diakhiri /.': 'CRS format: separate each extension with spaces and end it with /.',
  'Batasi jumlah request per alamat IP di seluruh upstream. Request yang melampaui batas mendapat HTTP 429.': 'Limit requests per client IP across all upstreams. Requests exceeding the limit receive HTTP 429.',
  'Hapus transaksi audit yang lebih lama dari masa penyimpanan. Pemeriksaan otomatis berjalan setiap jam dan prune maksimal sekali sehari.': 'Delete audit transactions older than the retention period. Checks run hourly and pruning occurs at most once per day.',
  'Simpan log selama (hari)': 'Keep logs for (days)',
  'Rule yang dinonaktifkan dari panel akan ditulis ke REQUEST-905-OPENWAF-CUSTOM.conf dan dibaca sebelum rule deteksi CRS. Exclusion global di halaman Exclusions juga tampil sebagai nonaktif di sini.': 'Rules disabled from the panel are written to REQUEST-905-OPENWAF-CUSTOM.conf and loaded before CRS detection rules. Global exclusions also appear as disabled here.',
  'Gunakan custom rule untuk kebutuhan spesifik aplikasi. ID dialokasikan otomatis pada mode Builder; mode Raw harus memakai ID 7 digit di rentang 9000000–9999999.': 'Use custom rules for application-specific requirements. IDs are allocated automatically in Builder mode; Raw mode must use a 7-digit ID in the 9000000–9999999 range.',
  'Hati-hati. Exclusion global menonaktifkan rule di semua trafik. Utamakan scope path atau host agar proteksi tetap aktif di bagian aplikasi lain.': 'Caution. A global exclusion disables the rule for all traffic. Prefer path or host scope so protection remains active elsewhere.',
  'Gunakan CIDR untuk rentang, contoh 10.0.0.0/8. Perubahan langsung dibuat sebagai rule ModSecurity dan WAF di-reload. Pastikan IP panel manajemen tidak ikut diblokir.': 'Use CIDR notation for ranges, for example 10.0.0.0/8. Changes are applied as ModSecurity rules and the WAF is reloaded. Do not block the management-panel IP.',
  'Selalu diblokir sebelum rule deteksi CRS dievaluasi.': 'Always blocked before CRS detection rules are evaluated.',
  'Gunakan port 8080 untuk routing hostname, atau pilih port publik apa pun dari 1–65535 untuk akses langsung melalui IP AsekWAF. Semua listener situs tetap melewati WAF.': 'Use port 8080 for hostname routing, or any public port from 1–65535 for direct access through the AsekWAF IP. Every site listener still passes through the WAF.',
  'Untuk request yang tidak cocok dengan situs mana pun': 'For requests that do not match any site',
  'Pertahankan Host header Kirim hostname asli ke upstream (berguna untuk virtual host aplikasi).': 'Preserve the Host header and send the original hostname upstream (useful for application virtual hosts).',
  'Untuk HTTPS dengan sertifikat publik, terminasi TLS di load balancer / reverse proxy depan, lalu teruskan trafik ke port 8080. Sertifikat default image hanya untuk pengujian.': 'For HTTPS with a public certificate, terminate TLS at the front load balancer or reverse proxy, then forward traffic to port 8080. The image default certificate is for testing only.',
  'WebSocket aktif': 'WebSocket enabled', 'Dikirim dari manager ke WAF': 'Sent from the manager to the WAF',
  'Isi untuk menguji routing dan proteksi WAF situs tertentu.': 'Set this to test routing and WAF protection for a specific site.',
  'Satu header per baris dengan format Nama: nilai.': 'One header per line using the Name: value format.', 'Response dari WAF dan hasil audit': 'WAF response and audit result',
  'Rentang IP yang dikendalikan penyerang/spam menurut Spamhaus (CIDR).': 'Attacker- or spam-controlled IP ranges according to Spamhaus (CIDR).',
  'IP yang terdeteksi sebagai host terkompromi oleh Emerging Threats.': 'IPs detected as compromised hosts by Emerging Threats.',
  'Daftar IP penyerang dari sensor CINS (Community Intelligence Network).': 'Attacker IPs reported by CINS community sensors.',
  'Agregasi 30+ blocklist; hanya IP dengan skor minimal 3 yang diambil.': 'Aggregation of 30+ blocklists; only IPs with a minimum score of 3 are included.',
  'Rule yang dinonaktifkan dari panel akan ditulis ke': 'Rules disabled from the panel are written to',
  'dan dibaca sebelum rule deteksi CRS. Exclusion global di halaman Exclusions juga tampil sebagai nonaktif di sini.': 'and loaded before CRS detection rules. Global exclusions also appear as disabled here.',
  'Gunakan custom rule untuk kebutuhan spesifik aplikasi. ID dialokasikan otomatis pada mode': 'Use custom rules for application-specific requirements. IDs are allocated automatically in',
  'harus memakai ID 7 digit di rentang': 'must use a 7-digit ID in the range',
  'Hati-hati.': 'Caution.',
  'Exclusion global menonaktifkan rule di semua trafik. Utamakan scope': 'A global exclusion disables the rule for all traffic. Prefer',
  'atau': 'or', 'agar proteksi tetap aktif di bagian aplikasi lain.': 'scope so protection remains active elsewhere.',
  'Gunakan CIDR untuk rentang, contoh': 'Use CIDR notation for ranges, for example',
  'Perubahan langsung dibuat sebagai rule ModSecurity dan WAF di-reload. Pastikan IP panel manajemen tidak ikut diblokir.': 'Changes are applied as ModSecurity rules and the WAF is reloaded. Do not block the management-panel IP.',
  '. Perubahan langsung dibuat sebagai rule ModSecurity dan WAF di-reload. Pastikan IP panel manajemen tidak ikut diblokir.': '. Changes are applied as ModSecurity rules and the WAF is reloaded. Do not block the management-panel IP.',
  'Gunakan port': 'Use port',
  'untuk routing hostname, atau pilih port publik apa pun dari': 'for hostname routing, or choose any public port from',
  'untuk akses langsung melalui IP AsekWAF. Semua listener situs tetap melewati WAF.': 'for direct access through the AsekWAF IP. Every site listener still passes through the WAF.',
  'Gunakan port 8080 untuk routing hostname, atau pilih port publik apa pun dari': 'Use port 8080 for hostname routing, or any public port from',
  'untuk akses langsung melalui IP AsekWAF. Semua listener situs tetap melewati WAF.': 'for direct access through the AsekWAF IP. Every site listener still passes through the WAF.',
  'Untuk HTTPS dengan sertifikat publik, terminasi TLS di load balancer / reverse proxy depan,': 'For HTTPS with a public certificate, terminate TLS at the front load balancer or reverse proxy,',
  'lalu teruskan trafik ke port 8080. Sertifikat default image hanya untuk pengujian.': 'then forward traffic to port 8080. The image default certificate is for testing only.',
  'Satu header per baris dengan format': 'One header per line using the format',
  'Nama: nilai': 'Name: value',
  'Format CRS: setiap ekstensi diapit spasi dan diakhiri': 'CRS format: separate each extension with spaces and end it with',
  'Pertahankan Host header': 'Preserve Host header',
  'Kirim hostname asli ke upstream (berguna untuk virtual host aplikasi).': 'Send the original hostname upstream (useful for application virtual hosts).',
  'Interval sinkronisasi (jam)': 'Synchronization interval (hours)',
  'Laporan komunitas honeypot/JAM (brute force, spam, scan).': 'Community honeypot/JAM reports (brute force, spam, scans).',
  'Hasil terakhir': 'Last result', 'Ukuran terakhir': 'Last size', 'belum diperiksa': 'not checked yet',
  'Periksa release resmi CRS di GitHub. Tuning, custom rule, exclusion, dan IP list dipertahankan saat update.': 'Check official CRS releases on GitHub. Tuning, custom rules, exclusions, and IP lists are preserved during updates.',
  'Update memerlukan akses internet dari container manager dan dapat memutus trafik beberapa detik saat reload.': 'Updating requires internet access from the manager container and may interrupt traffic for a few seconds during reload.',
  'Halaman respons untuk error WAF dan upstream. HTML dibuat lokal dan tetap tersedia saat aplikasi backend gagal.': 'Response pages for WAF and upstream errors. HTML is generated locally and remains available when the backend application fails.',
  'Bahasa halaman error': 'Error-page language',
  'Mengganti pilihan akan mengisi judul dan pesan dengan preset bahasa tersebut.': 'Changing this selection fills titles and messages with that language preset.',
  'Informasi container dan lokasi file yang dikelola panel.': 'Container information and file locations managed by the panel.',
  'Rentang 1–3650 hari. Default 30 hari.': 'Range: 1–3650 days. Default: 30 days.',
  'tersedia': 'available', 'Tidak ada perubahan': 'No changes',
  'Selalu diizinkan — menang atas blocklist.': 'Always allowed — takes precedence over the blocklist.',
  'Hanya skema + host + port, tanpa path. Contoh:': 'Scheme + host + port only, without a path. Example:',
  'Routing & keamanan': 'Routing & security', 'Situs diproteksi': 'Protected sites',
  'Routing berdasarkan hostname': 'Hostname-based routing',
  'Perubahan langsung di-reload ke Nginx': 'Changes are reloaded directly into Nginx',
  'Request normal': 'Normal request', 'Header tambahan': 'Additional headers',
  'Request akan tercatat di audit log bila memicu rule.': 'The request will be recorded in the audit log if it triggers a rule.',
  'Hasil': 'Result',
  'Paranoia lebih tinggi menambah rule deteksi, tetapi juga potensi false positive.': 'A higher paranoia level adds more detection rules, but also increases the potential for false positives.',
  'Dasar, false positive rendah': 'Basic, low false-positive rate', 'Seimbang (umum)': 'Balanced (common)',
  'Ketat': 'Strict', 'Sangat ketat': 'Very strict',
  'Request per menit / IP': 'Requests per minute / IP',
  'Kelonggaran request sesaat sebelum ditolak.': 'Temporary request allowance before rejection.',
  'Perilaku burst': 'Burst behavior', 'Nodelay — teruskan langsung': 'Nodelay — forward immediately',
  'Delay — antrekan bertahap': 'Delay — queue gradually',
  'Gabungkan blocklist komunitas menjadi rule ModSecurity. Allowlist lokal tetap menang.': 'Combine community blocklists into ModSecurity rules. The local allowlist always takes precedence.',
  'Status proteksi': 'Protection status', 'Sumber blocklist': 'Blocklist sources',
  'Gabungan blocklist level 1 FireHOL (CIDR). False positive relatif rendah.': 'Combined FireHOL level 1 blocklists (CIDR), with a relatively low false-positive rate.',
  'Status sistem': 'System status',
  'Coba lagi': 'Try again', 'IP tidak dikenal': 'Unknown IP', 'ya': 'yes', 'tidak': 'no',
  'Rule yang terpicu': 'Triggered rules', 'Tidak ada rule yang terpicu pada event ini.': 'No rules were triggered for this event.',
  'Sama dengan (@eq)': 'Equals (@eq)', 'semua trafik': 'all traffic', 'Global (semua trafik)': 'Global (all traffic)',
  'Rule ID yang dikecualikan': 'Excluded rule IDs', 'Pisahkan dengan koma. Gunakan ID rule CRS (6 digit).': 'Separate with commas. Use 6-digit CRS rule IDs.',
  'tanpa WebSocket': 'without WebSocket', 'verifikasi TLS': 'TLS verification', 'gagal': 'failed',
  'Port akses pada IP server, misalnya': 'Access port on the server IP, for example',
  'Gunakan': 'Use', 'untuk semua hostname, atau pisahkan beberapa hostname dengan koma.': 'for all hostnames, or separate multiple hostnames with commas.',
  'digunakan untuk routing hostname standar. Port': 'is used for standard hostname routing. Ports',
  'dan': 'and', 'dicadangkan AsekWAF.': 'are reserved by AsekWAF.',
  'Hanya untuk upstream https://.': 'Only for HTTPS upstreams.',
  'Pastikan hostname tidak dipakai situs lain. Setelah disimpan, Nginx divalidasi dengan': 'Make sure the hostname is not used by another site. After saving, Nginx is validated with',
  'bila gagal, perubahan dibatalkan otomatis.': 'if validation fails, the changes are rolled back automatically.',
  'Body request (untuk POST/PUT/PATCH)': 'Request body (for POST/PUT/PATCH)',
  'Request gagal.': 'Request failed.', 'Tidak ada response dari WAF.': 'No response from the WAF.',
  'Tidak ada rule yang terpicu.': 'No rules were triggered.',
  'Request lolos tanpa audit event. Ini normal untuk trafik bersih bila': 'The request passed without an audit event. This is normal for clean traffic when',
  'untuk mencatat semua request.': 'to log every request.', 'Header yang dikirim': 'Sent headers',
  'Ada perubahan belum disimpan': 'There are unsaved changes',
  'Engine Off membuat WAF hanya menjadi reverse proxy tanpa proteksi. Lanjutkan hanya untuk maintenance.': 'Engine Off turns the WAF into an unprotected reverse proxy. Continue only for maintenance.',
  'Detection paranoia tidak boleh lebih rendah dari blocking paranoia.': 'Detection paranoia cannot be lower than blocking paranoia.',
  '120 baris terakhir': 'Last 120 lines', 'Log tidak tersedia (Docker socket tidak dapat diakses).': 'Logs are unavailable (the Docker socket cannot be accessed).',
  'Container akan di-restart. Trafik akan terputus beberapa detik.': 'The container will restart. Traffic will be interrupted for a few seconds.',
  'Dikelola otomatis oleh AsekWAF': 'Managed automatically by AsekWAF',
  'File konfigurasi': 'Configuration files',
  'Custom rule baru': 'New custom rule', 'Nama rule': 'Rule name', 'Field / variabel': 'Field / variable',
  'Mengandung (@contains)': 'Contains (@contains)', 'Diawali (@beginsWith)': 'Begins with (@beginsWith)',
  'Diakhiri (@endsWith)': 'Ends with (@endsWith)', 'Kata kunci (@pm)': 'Keywords (@pm)',
  'Lebih besar (@gt)': 'Greater than (@gt)', 'Lebih kecil (@lt)': 'Less than (@lt)',
  'Tanpa tanda kutip pembuka/penutup. Escape karakter khusus regex bila perlu.': 'Do not include opening or closing quotes. Escape special regex characters when needed.',
  'deny (blokir)': 'deny (block)', 'pass (log saja)': 'pass (log only)',
  'allow (lewati pemeriksaan berikutnya)': 'allow (skip subsequent checks)',
  'Gunakan allow hanya untuk kondisi yang sangat spesifik dan terpercaya karena request yang cocok dapat melewati rule WAF berikutnya.': 'Use allow only for highly specific, trusted conditions because matching requests can bypass subsequent WAF rules.',
  'Pesan log': 'Log message', 'Catatan (opsional)': 'Note (optional)',
  'Aktifkan rule': 'Enable rule', 'Rule langsung diterapkan setelah disimpan.': 'The rule is applied immediately after saving.',
  'Buat rule': 'Create rule', 'Aktifkan exclusion': 'Enable exclusion', 'Buat exclusion': 'Create exclusion',
  'Virtual host baru': 'New virtual host', 'Nama situs': 'Site name', 'Port publik AsekWAF': 'AsekWAF public port',
  'Tanpa path. Gunakan https:// bila upstream TLS.': 'Do not include a path. Use https:// for a TLS upstream.',
  'Kirim hostname asli ke aplikasi.': 'Send the original hostname to the application.',
  'Aktifkan Upgrade/Connection header.': 'Enable Upgrade/Connection headers.',
  'Nonaktifkan hanya bila benar-benar diperlukan.': 'Disable only when absolutely necessary.',
  'Verifikasi TLS upstream': 'Verify upstream TLS', 'Aktifkan situs': 'Enable site', 'Buat situs': 'Create site',
  'Proteksi WAF': 'WAF protection', ', dan': ', and',
  'Mengirim…': 'Sending…', 'Tidak ada response': 'No response', 'Diblokir ModSecurity': 'Blocked by ModSecurity',
  'Terdeteksi / lolos': 'Detected / allowed', 'Buka event': 'Open event', 'Tidak ada rule terpicu': 'No rules triggered',
  '(body kosong)': '(empty body)',
  'Aktifkan': 'Enable', 'Catatan': 'Note', 'Nama': 'Name',
  'Hapus exclusion?': 'Delete exclusion?', 'Hapus exclusion': 'Delete exclusion',
  'Hapus entri IP?': 'Delete IP entry?', 'Entri akan dihapus dan WAF di-reload.': 'The entry will be deleted and the WAF reloaded.',
  'Hapus virtual host?': 'Delete virtual host?', 'Hapus situs': 'Delete site',
};

function localizedLegacyText(value) {
  if (preferences.language === 'id' || !value) return value;
  const original = String(value);
  const leading = original.match(/^\s*/)?.[0] || '';
  const trailing = original.match(/\s*$/)?.[0] || '';
  const trimmed = original.trim().replace(/\s+/g, ' ');
  if (!trimmed) return value;
  const key = Object.keys(I18N.id).find((name) => I18N.id[name] === trimmed);
  let translated = key ? t(key) : LEGACY_EN[trimmed];
  if (!translated) {
    translated = trimmed;
    for (const [source, target] of Object.entries(LEGACY_EN)) {
      if (source.length >= 8 && source.includes(' ') && translated.includes(source)) translated = translated.replaceAll(source, target);
    }
  }
  if (translated === trimmed) {
    translated = trimmed
      .replace(/(\d+) aktif · (\d+) nonaktif/i, '$1 enabled · $2 disabled')
      .replace(/(\d+) dari (\d+) situs aktif/i, '$1 of $2 sites enabled')
      .replace(/(\d+) \((\d+) aktif\)/i, '$1 ($2 enabled)')
      .replace(/(\d+) ENTRI\b/i, '$1 ENTRIES')
      .replace(/(\d+) SITUS\b/i, '$1 SITES');
    if (translated === trimmed) return value;
  }
  return `${leading}${translated}${trailing}`;
}

function localizeRendered(root = document) {
  if (!root || preferences.language === 'id') return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    if (node.parentElement?.closest('pre, code, script, style')) continue;
    node.nodeValue = localizedLegacyText(node.nodeValue);
  }
  root.querySelectorAll?.('[placeholder], [title], [aria-label]').forEach((element) => {
    for (const attr of ['placeholder', 'title', 'aria-label']) {
      if (element.hasAttribute(attr)) element.setAttribute(attr, localizedLegacyText(element.getAttribute(attr)));
    }
  });
}
function applyPreferences() {
  const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const activeTheme = preferences.theme === 'auto' ? (dark ? 'dark' : 'light') : preferences.theme;
  document.documentElement.dataset.theme = activeTheme;
  document.documentElement.dataset.bsTheme = activeTheme;
  document.documentElement.dataset.themePreference = preferences.theme;
  document.documentElement.lang = preferences.language;
  document.documentElement.dir = preferences.language === 'ar' ? 'rtl' : 'ltr';
}

async function syncErrorPagesLanguage(lang) {
  if (!state.session?.authenticated) return;
  try {
    const sec = await api('/api/security-controls');
    const ep = sec.errorPages || {};
    if (ep.language !== lang) {
      const preset = ERROR_PAGE_PRESETS[lang] || ERROR_PAGE_PRESETS.en;
      const pages = {};
      for (const code of [400, 403, 404, 429, 500, 502, 503, 504]) {
        pages[code] = {
          title: preset.pages[code][0],
          message: preset.pages[code][1],
        };
      }
      await api('/api/security-controls/error-pages', {
        method: 'PUT',
        body: {
          enabled: ep.enabled !== false,
          language: lang,
          brand: ep.brand || 'AsekWAF',
          accent: ep.accent || '#2dd4bf',
          supportText: preset.support,
          pages,
        },
      });
    }
  } catch {
    return false;
  }
  return true;
}
applyPreferences();
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (preferences.theme === 'auto') applyPreferences();
});

const state = {
  session: null,
  chrome: null,
  route: 'dashboard',
  rules: { page: 1, q: '', severity: '', status: '', pl: '', limit: 50 },
  events: { offset: 0, q: '', action: '', range: '24h', limit: 50 },
  settings: null,
  files: null,
};

class ApiError extends Error {
  constructor(message, status, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

async function api(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'X-Requested-With': 'openwaf' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(preferences.language === 'id' ? 'Tidak dapat menghubungi server AsekWAF.' : 'Unable to reach the AsekWAF server.', 0, null);
  }
  let data = {};
  try {
    data = await res.json();
  } catch {
    /* ignore non-json */
  }
  if (res.status === 401 && auth) {
    state.session = { authenticated: false, defaultPassword: data.defaultPassword };
    renderLogin();
  }
  if (!res.ok) {
    throw new ApiError(data.error || `Permintaan gagal (HTTP ${res.status})`, res.status, data.details);
  }
  return data;
}

const fmtNum = (value) => new Intl.NumberFormat(currentLocale()).format(Number(value) || 0);

const fmtDate = (iso) => {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return date.toLocaleString(currentLocale(), {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
};

const fmtTime = (iso) => {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString(currentLocale(), { hour: '2-digit', minute: '2-digit' });
};

function relTime(iso) {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return '—';
  const diff = Math.max(0, Date.now() - then);
  const relative = new Intl.RelativeTimeFormat(currentLocale(), { numeric: 'always' });
  if (diff < 60_000) return relative.format(-Math.floor(diff / 1000), 'second');
  if (diff < 3_600_000) return relative.format(-Math.floor(diff / 60_000), 'minute');
  if (diff < 86_400_000) return relative.format(-Math.floor(diff / 3_600_000), 'hour');
  return relative.format(-Math.floor(diff / 86_400_000), 'day');
}

const fmtBytes = (value) => {
  const num = Number(value) || 0;
  if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(num % (1024 * 1024) ? 1 : 0)} MB`;
  if (num >= 1024) return `${(num / 1024).toFixed(0)} KB`;
  return `${num} B`;
};

const SEV_CLASS = {
  CRITICAL: 'critical',
  ERROR: 'error',
  WARNING: 'warning',
  NOTICE: 'notice',
  INFO: 'info',
  DEBUG: 'outline',
  UNKNOWN: 'outline',
};

function sevBadge(sev) {
  const s = String(sev || 'UNKNOWN').toUpperCase();
  return `<span class="badge ${SEV_CLASS[s] || 'outline'}">${esc(s)}</span>`;
}

function actionBadge(event) {
  if (event.blocked) return `<span class="badge blocked">${t('blocked')}</span>`;
  if (event.ruleCount > 0 || (event.rules && event.rules.length)) {
    return `<span class="badge detected">${t('detected')}</span>`;
  }
  return `<span class="badge allowed">${t('allowed')}</span>`;
}

function statusBadge(status) {
  const code = Number(status) || 0;
  let cls = 'outline';
  if (code >= 200 && code < 300) cls = 'ok';
  else if (code >= 300 && code < 400) cls = 'info';
  else if (code >= 400 && code < 500) cls = 'warning';
  else if (code >= 500) cls = 'critical';
  return `<span class="badge ${cls}">${code || '—'}</span>`;
}

function pageHead(title, subtitle, actions = '') {
  const pageKeys = { Dashboard: 'dashboard', 'Audit Events': 'events', 'CRS Rules': 'rules', 'Custom Rules': 'custom', Exclusions: 'exclusions', 'IP Lists': 'ipLists', 'Reverse Proxy': 'proxy', 'Test Console': 'test', Settings: 'settings' };
  const localizedTitle = pageKeys[title] ? t(pageKeys[title]) : title;
  return `<div class="page-head">
    <div>
      <h1>${esc(localizedTitle)}</h1>
      ${subtitle ? `<p>${subtitle}</p>` : ''}
    </div>
    ${actions ? `<div class="page-actions">${actions}</div>` : ''}
  </div>`;
}

function emptyState(iconName, title, text) {
  return `<div class="empty">
    <div class="empty-icon">${icon(iconName, 'lg')}</div>
    <h3>${esc(title)}</h3>
    <p>${esc(text)}</p>
  </div>`;
}

const loadingBlock = () =>
  `<div class="loading-block"><span class="spinner"></span><span>${t('loading')}</span></div>`;

/* =========================================================================
   Toast / modal / drawer
   ========================================================================= */

function toast(message, type = 'info', timeout = 4200) {
  const el = document.createElement('div');
  // Bootstrap/AdminLTE hides `.toast:not(.show)`. Keep the `show` class on
  // our lightweight toast so CRUD feedback remains visible on every page.
  el.className = `toast show ${type}`;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  const iconName = type === 'ok' ? 'check' : type === 'error' ? 'alert' : 'info';
  el.innerHTML = `${icon(iconName)}<div class="toast-msg">${esc(message)}</div>
    <button class="toast-close" aria-label="${t('close')}">${icon('x', 'sm')}</button>`;
  const remove = () => el.remove();
  el.querySelector('.toast-close').addEventListener('click', remove);
  toastRoot.appendChild(el);
  localizeRendered(el);
  if (timeout) setTimeout(remove, timeout);
}

function closeModal() {
  modalRoot.innerHTML = '';
  document.body.classList.remove('no-scroll');
}

function openModal({ title, body, footer = '', wide = false }) {
  modalRoot.innerHTML = `<div class="overlay center" id="modalOverlay">
    <div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true">
      <div class="modal-head">
        <h2>${esc(title)}</h2>
        <button class="icon-btn" id="modalClose" aria-label="${t('close')}" style="margin-left:auto">${icon('x')}</button>
      </div>
      <div class="modal-body">${body}</div>
      ${footer ? `<div class="modal-foot">${footer}</div>` : ''}
    </div>
  </div>`;
  document.body.classList.add('no-scroll');
  const overlay = document.getElementById('modalOverlay');
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) closeModal();
  });
  document.getElementById('modalClose').addEventListener('click', closeModal);
  modalRoot.querySelectorAll('[data-close]').forEach((el) => el.addEventListener('click', closeModal));
  localizeRendered(modalRoot);
  const firstInput = modalRoot.querySelector('input, select, textarea');
  if (firstInput) setTimeout(() => firstInput.focus(), 40);
  return modalRoot.querySelector('.modal');
}

function confirmDialog({ title, message, confirmLabel = t('apply'), danger = true }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      closeModal();
      resolve(value);
    };
    openModal({
      title,
      body: `<p style="margin:0;color:var(--muted);line-height:1.7">${esc(message)}</p>`,
      footer: `<button class="btn" id="confirmCancel">${t('cancel')}</button>
        <button class="btn ${danger ? 'danger' : 'primary'}" id="confirmOk">${esc(confirmLabel)}</button>`,
    });
    document.getElementById('confirmCancel').addEventListener('click', () => finish(false));
    document.getElementById('confirmOk').addEventListener('click', () => finish(true));
    modalRoot.querySelector('#modalOverlay').addEventListener('click', (event) => {
      if (event.target.id === 'modalOverlay') finish(false);
    });
  });
}

function closeDrawer() {
  drawerRoot.innerHTML = '';
  document.body.classList.remove('no-scroll');
}

function openDrawer({ title, subtitle = '', body, footer = '' }) {
  drawerRoot.innerHTML = `<div class="overlay" id="drawerOverlay">
    <div class="drawer" role="dialog" aria-modal="true">
      <div class="drawer-head">
        <div>
          <h2>${esc(title)}</h2>
          ${subtitle ? `<div class="sub">${subtitle}</div>` : ''}
        </div>
        <button class="icon-btn" id="drawerClose" aria-label="${t('close')}" style="margin-left:auto">${icon('x')}</button>
      </div>
      <div class="drawer-body">${body}</div>
      ${footer ? `<div class="drawer-foot">${footer}</div>` : ''}
    </div>
  </div>`;
  document.body.classList.add('no-scroll');
  const overlay = document.getElementById('drawerOverlay');
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) closeDrawer();
  });
  document.getElementById('drawerClose').addEventListener('click', closeDrawer);
  drawerRoot.querySelectorAll('[data-close]').forEach((el) => el.addEventListener('click', closeDrawer));
  localizeRendered(drawerRoot);
}

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (modalRoot.innerHTML) closeModal();
  else if (drawerRoot.innerHTML) closeDrawer();
});

async function copyText(text) {
  try {
    if (window.isSecureContext && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = String(text);
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      textarea.style.pointerEvents = 'none';
      document.body.appendChild(textarea);
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);
      const copied = document.execCommand('copy');
      textarea.remove();
      if (!copied) throw new Error('Legacy clipboard command was rejected');
    }
    toast(t('copied'), 'ok');
  } catch {
    // Some browsers expose the Clipboard API but reject it because of policy
    // or permissions. Retry with the selection-based fallback.
    try {
      const textarea = document.createElement('textarea');
      textarea.value = String(text);
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      const copied = document.execCommand('copy');
      textarea.remove();
      if (!copied) throw new Error('Clipboard unavailable');
      toast(t('copied'), 'ok');
    } catch {
      toast(t('copyFailed'), 'error');
    }
  }
}

function showApiError(err) {
  toast(err.message || t('genericError'), 'error');
  if (err.details && err.details.output) {
    openModal({
      title: t('validationFailed'),
      body: `<div class="note danger" style="margin-bottom:12px">${icon('alert')}
        <div>${t('changesCancelled')}</div>
      </div><pre class="code">${esc(err.details.output)}</pre>`,
      footer: `<button class="btn" data-close> ${t('close')}</button>`,
    });
  }
}

function setBusy(button, busy, label = t('saving')) {
  if (!button) return;
  if (busy) {
    button.dataset.original = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span>${esc(label)}`;
  } else {
    button.disabled = false;
    if (button.dataset.original) button.innerHTML = button.dataset.original;
  }
}

function preferenceControls() {
  return `<label class="preference-control" title="${t('theme')}">
    ${icon('eye', 'sm')}<span class="preference-label">${t('theme')}</span>
    <select data-preference="theme" aria-label="${t('theme')}">
      <option value="auto" ${preferences.theme === 'auto' ? 'selected' : ''}>${t('auto')}</option>
      <option value="light" ${preferences.theme === 'light' ? 'selected' : ''}>${t('light')}</option>
      <option value="dark" ${preferences.theme === 'dark' ? 'selected' : ''}>${t('dark')}</option>
    </select>
  </label>`;
}

function bindPreferenceControls() {
  document.querySelectorAll('[data-preference="theme"]').forEach((select) => {
    select.addEventListener('change', () => {
      preferences.theme = select.value;
      localStorage.setItem('openwaf.theme', preferences.theme);
      applyPreferences();
      document.querySelectorAll('[data-preference="theme"]').forEach((item) => { item.value = preferences.theme; });
    });
  });
}

/* =========================================================================
   Login + shell
   ========================================================================= */

function renderLogin(errorMessage = '') {
  const defaultPassword = state.session?.defaultPassword;
  appEl.innerHTML = `<div class="login-page">
    <div class="login-art">
      <div class="brand-lockup">
        <div class="brand-mark">${icon('shield')}</div>
        <div>
          <div class="brand-name">Asek<span>WAF</span></div>
          <div class="brand-sub">Open-source WAF console</div>
        </div>
      </div>
      <div class="login-hero">
        <h2>${t('loginHero')}</h2>
        <p>${t('loginCopy')}</p>
        <div class="login-features">
          <span class="login-feature">${icon('shield', 'sm')} ModSecurity v3</span>
          <span class="login-feature">${icon('rules', 'sm')} OWASP CRS</span>
          <span class="login-feature">${icon('network', 'sm')} Reverse proxy</span>
          <span class="login-feature">${icon('activity', 'sm')} Audit log</span>
        </div>
      </div>
      <div class="login-meta">
        <span>AsekWAF 1.0</span>
        <span>Open source • MIT License</span>
      </div>
    </div>
    <div class="login-form-wrap">
      <div class="login-mobile-brand brand-lockup" aria-label="AsekWAF">
        <div class="brand-mark">${icon('shield')}</div>
        <div>
          <div class="brand-name">Asek<span>WAF</span></div>
          <div class="brand-sub">Open-source WAF console</div>
        </div>
      </div>
      <div class="login-card">
        <div class="login-preferences">${preferenceControls()}</div>
        <h1>${t('loginTitle')}</h1>
        <p class="lead">${t('loginLead')}</p>
        ${defaultPassword
          ? `<div class="login-alert">${icon('alert')}
              <div>${t('defaultPassword')}</div>
            </div>`
          : ''}
        <form id="loginForm" novalidate>
          <div class="field">
            <label for="password">${t('adminPassword')}</label>
            <div class="password-wrap">
              <input id="password" name="password" type="password" autocomplete="current-password"
                placeholder="${t('enterPassword')}" autofocus required />
              <button type="button" class="password-toggle" id="togglePassword" aria-label="${t('showPassword')}">
                ${icon('eye')}
              </button>
            </div>
          </div>
          <button class="btn primary" type="submit" id="loginBtn" style="width:100%;height:40px">
            ${icon('lock', 'sm')} ${t('signIn')}
          </button>
          <div class="login-error" id="loginError">${esc(errorMessage)}</div>
        </form>
        <div class="login-footer">AsekWAF • Open-source • ModSecurity + OWASP CRS</div>
      </div>
    </div>
  </div>`;

  const form = document.getElementById('loginForm');
  const input = document.getElementById('password');
  const errorEl = document.getElementById('loginError');
  const button = document.getElementById('loginBtn');
  bindPreferenceControls();
  document.getElementById('togglePassword').addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    input.focus();
  });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorEl.textContent = '';
    if (!input.value) {
      errorEl.textContent = t('passwordRequired');
      return;
    }
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span> ${t('verifying')}`;
    try {
      await api('/api/login', { method: 'POST', body: { password: input.value }, auth: false });
      state.session = { authenticated: true, defaultPassword: false };
      if (!window.location.hash) history.replaceState(null, '', '#/dashboard');
      await mountShell();
      applyRoute();
    } catch (err) {
      errorEl.textContent = err.message;
      button.disabled = false;
      button.innerHTML = `${icon('lock', 'sm')} ${t('signIn')}`;
      input.focus();
      input.select();
    }
  });
}

async function mountShell() {
  const savedSidebar = localStorage.getItem('openwaf.sidebarCollapsed') === 'true';
  appEl.innerHTML = `<div class="wrapper shell adminlte-shell ${savedSidebar ? 'sidebar-collapsed' : ''}" id="appShell">
    <aside class="main-sidebar sidebar-dark-primary elevation-4 sidebar" id="sidebar">
      <a class="brand-link sidebar-head" href="#/dashboard" aria-label="AsekWAF dashboard">
        <div class="brand-lockup">
          <div class="brand-mark">${icon('shield')}</div>
          <div>
            <div class="brand-name">Asek<span>WAF</span></div>
            <div class="brand-sub">${t('console')}</div>
          </div>
        </div>
      </a>
      <div class="adminlte-sidebar-body">
      <nav class="sidebar-nav mt-2" aria-label="${t('navigation')}">
        <div class="nav-group">
          <div class="nav-label">${t('monitor')}</div>
          <button class="nav-link nav-item" data-route="dashboard" title="${t('dashboard')}">${icon('dashboard')}<span>${t('dashboard')}</span></button>
          <button class="nav-link nav-item" data-route="events" title="${t('events')}">${icon('activity')}<span>${t('events')}</span></button>
        </div>
        <div class="nav-group">
          <div class="nav-label">${t('protection')}</div>
          <button class="nav-link nav-item" data-route="rules" title="${t('rules')}">${icon('rules')}<span>${t('rules')}</span></button>
          <button class="nav-link nav-item" data-route="custom" title="${t('custom')}">${icon('code')}<span>${t('custom')}</span></button>
          <button class="nav-link nav-item" data-route="exclusions" title="${t('exclusions')}">${icon('filter')}<span>${t('exclusions')}</span></button>
          <button class="nav-link nav-item" data-route="iplists" title="${t('ipLists')}">${icon('ban')}<span>${t('ipLists')}</span></button>
          <button class="nav-link nav-item" data-route="proxy" title="${t('proxy')}">${icon('network')}<span>${t('proxy')}</span></button>
        </div>
        <div class="nav-group">
          <div class="nav-label">${t('tools')}</div>
          <button class="nav-link nav-item" data-route="test" title="${t('test')}">${icon('terminal')}<span>${t('test')}</span></button>
          <button class="nav-link nav-item" data-route="settings" title="${t('settings')}">${icon('settings')}<span>${t('settings')}</span></button>
        </div>
      </nav>
      <div class="sidebar-foot">
        <div class="status-card">
          <div class="status-line"><span class="dot" id="sideWafDot"></span> Engine
            <span class="status-value" id="sideEngine">${t('checking')}</span>
          </div>
          <div class="status-line">${icon('shield', 'sm')} CRS
            <span class="status-value" id="sideCrs">—</span>
          </div>
          <div class="status-line">${icon('network', 'sm')} Proxy
            <span class="status-value" id="sideProxy">—</span>
          </div>
        </div>
        <div class="app-version" id="sideVersion">AsekWAF</div>
      </div>
      </div>
    </aside>
    <div class="sidebar-scrim" id="sidebarScrim" hidden></div>
    <div class="content-wrapper main">
      <header class="main-header navbar navbar-expand navbar-dark topbar">
        <button class="icon-btn mobile-menu" id="menuBtn" aria-label="${t('collapse')}" aria-expanded="${!savedSidebar}" title="${t('collapse')}">${icon('menu')}</button>
        <div>
          <div class="topbar-title">AsekWAF</div>
          <div class="topbar-sub">Open-source • ModSecurity + OWASP CRS</div>
        </div>
        <div class="topbar-right">
          <div class="topbar-preferences">${preferenceControls()}</div>
          <button class="btn sm" id="reloadBtn" title="${t('validateAndReload')}">
            ${icon('refresh', 'sm')}<span class="btn-label">${t('reload')}</span>
          </button>
          <button class="icon-btn" id="logoutBtn" title="${t('logout')}" aria-label="${t('logout')}">${icon('logout')}</button>
        </div>
      </header>
      <main class="content view" id="view">${loadingBlock()}</main>
    </div>
  </div>`;

  bindPreferenceControls();
  document.querySelectorAll('[data-route]').forEach((el) => {
    el.addEventListener('click', () => {
      window.location.hash = `#/${el.dataset.route}`;
      closeSidebar();
    });
  });
  document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST' });
    } catch {
      /* ignore */
    }
    state.session = { authenticated: false };
    renderLogin();
  });
  document.getElementById('reloadBtn').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, 'Reload…');
    try {
      const result = await api('/api/system/reload', { method: 'POST' });
      toast(result.message || 'WAF berhasil di-reload.', 'ok');
      refreshChrome();
    } catch (err) {
      showApiError(err);
    } finally {
      setBusy(button, false);
    }
  });
  const menuBtn = document.getElementById('menuBtn');
  menuBtn.addEventListener('click', () => {
    const shell = document.getElementById('appShell');
    if (window.matchMedia('(min-width: 981px)').matches) {
      const collapsed = shell.classList.toggle('sidebar-collapsed');
      localStorage.setItem('openwaf.sidebarCollapsed', String(collapsed));
      menuBtn.setAttribute('aria-expanded', String(!collapsed));
      menuBtn.setAttribute('aria-label', collapsed ? t('expand') : t('collapse'));
      menuBtn.title = collapsed ? t('expand') : t('collapse');
      return;
    }
    document.getElementById('sidebar').classList.add('open');
    const scrim = document.getElementById('sidebarScrim');
    scrim.hidden = false;
    scrim.addEventListener('click', closeSidebar, { once: true });
  });
  refreshChrome();
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  const scrim = document.getElementById('sidebarScrim');
  if (sidebar) sidebar.classList.remove('open');
  if (scrim) scrim.hidden = true;
}

function setActiveNav(route) {
  document.querySelectorAll('[data-route]').forEach((el) => {
    el.classList.toggle('active', el.dataset.route === route);
  });
}

async function refreshChrome() {
  try {
    const data = await api('/api/overview');
    state.chrome = data;
    updateChrome(data);
  } catch {
    /* silent */
  }
}

function updateChrome(data) {
  if (!data) return;
  const engine = data.waf.engineMode || '—';
  const online = data.waf.online;
  const sideEngine = document.getElementById('sideEngine');
  const sideDot = document.getElementById('sideWafDot');
  if (sideEngine) sideEngine.textContent = online ? engine : data.waf.dockerAvailable ? 'offline' : 'n/a';
  if (sideDot) {
    sideDot.className = `dot ${online && engine === 'On' ? 'ok' : online && engine === 'DetectionOnly' ? 'warn' : 'bad'}`;
  }
  const sideCrs = document.getElementById('sideCrs');
  if (sideCrs) sideCrs.textContent = data.crs.version || '—';
  const sideProxy = document.getElementById('sideProxy');
  if (sideProxy) sideProxy.textContent = `${data.reverseProxy?.enabledSites ?? 0} ${t('sites')}`;
  const sideVersion = document.getElementById('sideVersion');
  if (sideVersion) sideVersion.textContent = `AsekWAF v${data.version || '—'}`;
}

/* =========================================================================
   Router
   ========================================================================= */

function applyRoute() {
  if (!state.session?.authenticated) return;
  const route = (window.location.hash.replace(/^#\/?/, '') || 'dashboard').split('?')[0];
  const valid = ['dashboard', 'events', 'rules', 'custom', 'exclusions', 'iplists', 'proxy', 'test', 'settings'];
  state.route = valid.includes(route) ? route : 'dashboard';
  setActiveNav(state.route);
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });

  const renderers = {
    dashboard: renderDashboard,
    events: renderEvents,
    rules: renderRules,
    custom: renderCustomRules,
    exclusions: renderExclusions,
    iplists: renderIpLists,
    proxy: renderProxy,
    test: renderTest,
    settings: renderSettings,
  };
  Promise.resolve(renderers[state.route]())
    .then(() => localizeRendered(document.getElementById('view')))
    .catch((err) => renderViewError(err));
}

function renderViewError(err) {
  const view = document.getElementById('view');
  if (!view) return;
  view.innerHTML = `<div class="card" style="max-width:640px;margin:40px auto">
    <div class="card-body">
      <div class="note danger" style="margin-bottom:14px">${icon('alert')}
        <div><strong>${t('pageLoadFailed')}</strong><br />${esc(err.message || err)}</div>
      </div>
      <button class="btn" id="retryBtn">${icon('refresh', 'sm')} ${t('retry')}</button>
    </div>
  </div>`;
  const retry = document.getElementById('retryBtn');
  if (retry) retry.addEventListener('click', applyRoute);
}

/* =========================================================================
   Dashboard
   ========================================================================= */

async function renderDashboard() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const [data, geo] = await Promise.all([
    api('/api/overview'),
    api('/api/stats/countries?hours=24').catch((err) => ({ countries: [], localEvents: 0, error: err.message })),
  ]);
  state.chrome = data;
  updateChrome(data);
  const stats = data.stats || {};
  const tl = stats.timeline || [];
  const recent = data.recentEvents || [];
  const waf = data.waf;
  const engineClass = waf.engineMode === 'On' ? 'ok' : waf.engineMode === 'DetectionOnly' ? 'warning' : 'offline';

  view.innerHTML = `
    ${pageHead(
      t('dashboard'),
      t('dashSubtitle'),
      `<button class="btn sm" id="dashRefresh">${icon('refresh', 'sm')} ${t('refresh')}</button>
       <a class="btn sm primary" href="#/test">${icon('terminal', 'sm')} ${t('testRequest')}</a>`
    )}
    <div class="grid grid-kpi">
      <div class="kpi">
        <div class="kpi-top"><span>${t('audit24')}</span><span class="kpi-icon">${icon('activity', 'sm')}</span></div>
        <div class="kpi-value">${fmtNum(stats.total || 0)}</div>
        <div class="kpi-foot">${fmtNum(stats.uniqueIps || 0)} ${t('uniqueIps')} · ${fmtNum(stats.allowed || 0)} ${t('passed')}</div>
      </div>
      <div class="kpi danger">
        <div class="kpi-top"><span>${t('blocked24')}</span><span class="kpi-icon">${icon('ban', 'sm')}</span></div>
        <div class="kpi-value">${fmtNum(stats.blocked || 0)}</div>
        <div class="kpi-foot">${stats.blockedPct || 0}% ${t('totalEvents')}</div>
      </div>
      <div class="kpi warn">
        <div class="kpi-top"><span>${t('detectedOnly')}</span><span class="kpi-icon">${icon('eye', 'sm')}</span></div>
        <div class="kpi-value">${fmtNum(stats.detected || 0)}</div>
        <div class="kpi-foot">${t('anomalyHint')}</div>
      </div>
      <div class="kpi ok">
        <div class="kpi-top"><span>CRS rules</span><span class="kpi-icon">${icon('rules', 'sm')}</span></div>
        <div class="kpi-value">${fmtNum(data.crs.total || 0)}</div>
        <div class="kpi-foot">${fmtNum(data.crs.disabled || 0)} ${t('disabled')} · ${fmtNum(data.crs.customRules || 0)} ${t('customShort')}</div>
      </div>
    </div>

    <div class="grid grid-dash mt-16">
      <div class="card dash-chart-full">
        <div class="card-head">
          <div>
            <h3>${t('eventTrend')}</h3>
            <div class="sub">${t('eventTrendSub')}</div>
          </div>
          <div class="card-head-actions">
            <a class="btn sm ghost" href="#/events">${t('allEvents')} ${icon('arrow-right', 'sm')}</a>
          </div>
        </div>
        <div class="chart-wrap">${timelineChart(tl)}</div>
        <div class="chart-legend">
          <span><span class="legend-dot" style="background:#fb7185"></span>${t('blocked')}</span>
          <span><span class="legend-dot" style="background:#fbbf24"></span>${t('detected')}</span>
          <span><span class="legend-dot" style="background:rgba(56,189,248,.4)"></span>${t('allowed')}</span>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h3>${t('wafStatus')}</h3><div class="sub">ModSecurity engine & container</div></div>
          <span class="badge ${engineClass}">${esc(waf.engineMode)}</span>
        </div>
        <div class="card-body">
          <div class="status-panel">
            <div class="status-item">
              <span class="dot ${waf.online ? 'ok' : waf.dockerAvailable ? 'bad' : 'warn'}"></span>
              <span class="label">Container</span>
              <span class="value">${waf.online ? 'online' : waf.dockerAvailable ? 'offline' : t('unavailable')}</span>
            </div>
            <div class="status-item"><span class="label">${t('containerName')}</span><span class="value">${esc(waf.container)}</span></div>
            <div class="status-item"><span class="label">${t('engineMode')}</span><span class="value">${esc(waf.engineMode)}</span></div>
            <div class="status-item"><span class="label">${t('auditEngine')}</span><span class="value">${esc(waf.auditEngine)}</span></div>
            <div class="status-item"><span class="label">${t('paranoia')}</span><span class="value">PL ${data.settings.paranoia}</span></div>
            <div class="status-item"><span class="label">${t('threshold')}</span><span class="value">in ${data.settings.inboundThreshold} / out ${data.settings.outboundThreshold}</span></div>
            <div class="status-item"><span class="label">${t('crsVersion')}</span><span class="value">${esc(data.crs.version)}</span></div>
            <div class="status-item"><span class="label">${t('auditLog')}</span><span class="value">${fmtNum(data.audit.events)} event${data.audit.error ? ' · error' : ''}</span></div>
            <div class="status-item"><span class="label">${t('proxy')}</span><span class="value">${data.reverseProxy.enabledSites} ${t('sites')}</span></div>
          </div>
          <div class="row mt-16">
            <a class="btn sm" href="#/settings">${icon('settings', 'sm')} ${t('settings')}</a>
            <a class="btn sm" href="#/proxy">${icon('network', 'sm')} ${t('proxy')}</a>
          </div>
          ${data.defaultPassword
            ? `<div class="note warn" style="margin-top:14px">${icon('alert')}
                <div>${t('defaultWarning')}</div>
              </div>`
            : ''}
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h3>${t('attackMap')}</h3><div class="sub">${t('attackMapSub')}</div></div>
          <span class="badge outline">GeoIP</span>
        </div>
        ${renderAttackMap(geo)}
      </div>
    </div>

    <div class="grid grid-2 mt-16">
      <div class="card">
        <div class="card-head"><div><h3>${t('topRules')}</h3><div class="sub">${t('last24')}</div></div>
          <a class="btn sm ghost" href="#/rules">${t('openRules')} ${icon('arrow-right', 'sm')}</a>
        </div>
        ${renderTopRules(stats.topRules || [])}
      </div>
      <div class="card">
        <div class="card-head"><div><h3>${t('topIps')}</h3><div class="sub">${t('basedAudit')}</div></div>
          <a class="btn sm ghost" href="#/iplists">${t('ipLists')} ${icon('arrow-right', 'sm')}</a>
        </div>
        ${renderTopIps(stats.topIps || [])}
      </div>
    </div>

    <div class="card mt-16">
      <div class="card-head">
        <div><h3>${t('latestEvents')}</h3><div class="sub">${t('clickDetail')}</div></div>
        <div class="card-head-actions"><button class="btn sm ghost" id="dashRefresh2">${icon('refresh', 'sm')} ${t('refresh')}</button></div>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>${t('time')}</th><th>${t('action')}</th><th>${t('thIp')}</th><th>${t('request')}</th><th>${t('status')}</th><th>${t('rule')}</th></tr></thead>
          <tbody>
            ${recent.length ? recent.map(eventRow).join('') : `<tr><td colspan="6">${emptyState('activity', t('noEvents'), t('noEventsText'))}</td></tr>`}
          </tbody>
        </table>
      </div>
      <div class="table-foot">
        <span>${fmtNum(stats.total || 0)} ${t('eventsIn24h')}</span>
        <span class="spacer"></span>
        <a class="btn sm ghost" href="#/events">${t('viewAll')} ${icon('arrow-right', 'sm')}</a>
      </div>
    </div>`;

  bindEventRows();
  bindTimelineChart();
  const refresh = () => renderDashboard();
  ['dashRefresh', 'dashRefresh2'].forEach((id) => {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', refresh);
  });
}

function renderAttackMap(data) {
  const countries = Array.isArray(data?.countries) ? data.countries : [];
  const displayNames = typeof Intl.DisplayNames === 'function'
    ? new Intl.DisplayNames([currentLocale()], { type: 'region' })
    : null;
  const countryName = (code) => {
    try { return displayNames?.of(code) || code; } catch { return code; }
  };
  const max = Math.max(1, ...countries.map((item) => Number(item.count) || 0));
  const dots = countries
    .filter((item) => Number.isFinite(item.latitude) && Number.isFinite(item.longitude))
    .map((item) => {
      const left = Math.max(1, Math.min(99, ((Number(item.longitude) + 180) / 360) * 100));
      const top = Math.max(2, Math.min(98, ((90 - Number(item.latitude)) / 180) * 100));
      const size = 8 + Math.round(((Number(item.count) || 0) / max) * 13);
      return `<span class="attack-dot" style="left:${left}%;top:${top}%;width:${size}px;height:${size}px" title="${esc(countryName(item.country))}: ${fmtNum(item.count)} event"></span>`;
    })
    .join('');
  const list = countries.slice(0, 6).map((item) => `<div class="geo-row">
    <span class="geo-code">${esc(item.country)}</span><span class="geo-name">${esc(countryName(item.country))}</span>
    <span class="geo-count">${fmtNum(item.count)}</span>
  </div>`).join('');
  return `<div class="geo-card-body">
    <div class="attack-map" role="img" aria-label="${t('attackMap')}">
      <img class="world-map" src="/world-map.svg?v=ne110m-1" alt="" aria-hidden="true" />
      ${dots}
      ${!dots ? `<div class="map-empty">${esc(data?.error || t('noGeoAttacks'))}</div>` : ''}
    </div>
    <div class="geo-list">${list || `<div class="muted small">${t('noGeoAttacks')}</div>`}</div>
    <div class="geo-foot">${fmtNum(data?.localEvents || 0)} ${t('localTraffic')} · ${t('geoPrivacy')}</div>
  </div>`;
}

function renderTopRules(rules) {
  if (!rules.length) {
    return `<div class="table-empty">${icon('shield')}<div>${t('noRule')}</div></div>`;
  }
  return `<div class="table-wrap"><table class="data">
    <thead><tr><th>ID</th><th>${t('thRule')}</th><th style="text-align:right">${t('thHit')}</th></tr></thead>
    <tbody>${rules
      .map(
        (rule) => `<tr class="clickable" data-goto-rule="${rule.id}">
          <td class="mono">${rule.id}</td>
          <td><div class="rule-name truncate" style="max-width:420px">${esc(rule.msg)}</div>
            <div class="cell-sub">${sevBadge(rule.severity)}</div></td>
          <td class="mono" style="text-align:right">${fmtNum(rule.count)}</td>
        </tr>`
      )
      .join('')}</tbody></table></div>`;
}

function renderTopIps(ips) {
  if (!ips.length) {
    return `<div class="table-empty">${icon('network')}<div>${t('noIp')}</div></div>`;
  }
  return `<div class="table-wrap"><table class="data">
    <thead><tr><th>${t('thIp')}</th><th style="text-align:right">Event</th><th style="text-align:right">${t('blocked')}</th></tr></thead>
    <tbody>${ips
      .map(
        (item) => `<tr>
          <td class="mono">${esc(item.ip)}</td>
          <td class="mono" style="text-align:right">${fmtNum(item.count)}</td>
          <td style="text-align:right"><span class="badge ${item.blocked ? 'blocked' : 'outline'}">${fmtNum(item.blocked)}</span></td>
        </tr>`
      )
      .join('')}</tbody></table></div>`;
}

function timelineChart(points) {
  if (!points.length) return `<div class="chart-empty">${t('timelineEmpty')}</div>`;
  const width = 900;
  const height = 220;
  const pad = { l: 38, r: 10, t: 12, b: 26 };
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const max = Math.max(1, ...points.map((p) => p.blocked + p.detected + p.allowed));
  const step = innerW / points.length;
  const barW = Math.max(4, Math.min(24, step * 0.62));
  const bars = points
    .map((point, index) => {
      const total = point.blocked + point.detected + point.allowed;
      const x = pad.l + index * step + (step - barW) / 2;
      const hBlocked = (point.blocked / max) * innerH;
      const hDetected = (point.detected / max) * innerH;
      const hAllowed = (point.allowed / max) * innerH;
      let y = pad.t + innerH;
      const parts = [];
      if (hBlocked > 0) {
        y -= hBlocked;
        parts.push(`<rect x="${x}" y="${y}" width="${barW}" height="${hBlocked}" rx="3" fill="url(#chartBlocked)" />`);
      }
      if (hDetected > 0) {
        y -= hDetected;
        parts.push(`<rect x="${x}" y="${y}" width="${barW}" height="${hDetected}" rx="3" fill="url(#chartDetected)" />`);
      }
      if (hAllowed > 0) {
        y -= hAllowed;
        parts.push(`<rect x="${x}" y="${y}" width="${barW}" height="${hAllowed}" rx="3" fill="url(#chartAllowed)" />`);
      }
      if (!total) {
        parts.push(`<rect x="${x}" y="${pad.t + innerH - 2}" width="${barW}" height="2" rx="1" fill="#22344f" />`);
      }
      parts.push(`<rect class="chart-hit" x="${pad.l + index * step}" y="${pad.t}" width="${step}" height="${innerH}" data-time="${esc(fmtTime(point.t))}" data-blocked="${point.blocked}" data-detected="${point.detected}" data-allowed="${point.allowed}" data-total="${total}" />`);
      return `<g class="chart-column">${parts.join('')}</g>`;
    })
    .join('');

  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((frac) => {
      const y = pad.t + innerH - frac * innerH;
      return `<line x1="${pad.l}" y1="${y}" x2="${width - pad.r}" y2="${y}" class="chart-grid-line" />
        <text x="${pad.l - 8}" y="${y + 4}" text-anchor="end" class="chart-axis-text">${Math.round(max * frac)}</text>`;
    })
    .join('');

  const labels = points
    .map((point, index) => {
      if (index % 6 !== 0 && index !== points.length - 1) return '';
      const x = pad.l + index * step + step / 2;
      return `<text x="${x}" y="${height - 6}" text-anchor="middle" class="chart-axis-text">${fmtTime(point.t)}</text>`;
    })
    .join('');

  return `<div class="modern-chart">
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${t('chartAria')}">
      <defs>
        <linearGradient id="chartBlocked" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#ff8da1"/><stop offset="1" stop-color="#f43f5e"/></linearGradient>
        <linearGradient id="chartDetected" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#fde68a"/><stop offset="1" stop-color="#f59e0b"/></linearGradient>
        <linearGradient id="chartAllowed" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#67e8f9"/><stop offset="1" stop-color="#0284c7"/></linearGradient>
      </defs>
      ${grid}${bars}${labels}
    </svg>
    <div class="chart-tooltip" role="status" aria-hidden="true"></div>
  </div>`;
}

function bindTimelineChart() {
  const chart = document.querySelector('.modern-chart');
  const tooltip = chart?.querySelector('.chart-tooltip');
  if (!chart || !tooltip) return;
  chart.querySelectorAll('.chart-hit').forEach((hit) => {
    hit.addEventListener('pointerenter', () => {
      tooltip.innerHTML = `<div class="chart-tooltip-time">${esc(hit.dataset.time)}</div>
        <div class="chart-tooltip-row"><i class="blocked"></i><span>${t('blocked')}</span><strong>${fmtNum(hit.dataset.blocked)}</strong></div>
        <div class="chart-tooltip-row"><i class="detected"></i><span>${t('detected')}</span><strong>${fmtNum(hit.dataset.detected)}</strong></div>
        <div class="chart-tooltip-row"><i class="allowed"></i><span>${t('allowed')}</span><strong>${fmtNum(hit.dataset.allowed)}</strong></div>
        <div class="chart-tooltip-total"><span>${t('chartTotal')}</span><strong>${fmtNum(hit.dataset.total)} ${t('chartEvents')}</strong></div>`;
      tooltip.classList.add('show');
      tooltip.setAttribute('aria-hidden', 'false');
    });
    hit.addEventListener('pointermove', (event) => {
      const box = chart.getBoundingClientRect();
      const x = Math.max(90, Math.min(box.width - 90, event.clientX - box.left));
      tooltip.style.left = `${x}px`;
      tooltip.style.top = `${Math.max(8, event.clientY - box.top - tooltip.offsetHeight - 14)}px`;
    });
    hit.addEventListener('pointerleave', () => {
      tooltip.classList.remove('show');
      tooltip.setAttribute('aria-hidden', 'true');
    });
  });
}

function eventRow(event) {
  return `<tr class="clickable" data-event="${esc(event.uid)}">
    <td class="nowrap"><span class="mono small">${fmtDate(event.ts)}</span><div class="cell-sub">${relTime(event.ts)}</div></td>
    <td>${actionBadge(event)}</td>
    <td class="mono">${esc(event.ip || '—')}</td>
    <td><div class="truncate" style="max-width:420px"><span class="mono small">${esc(event.method)}</span> ${esc(event.uri || '/')}</div>
      <div class="cell-sub truncate" style="max-width:420px">${esc(event.host || '')}</div></td>
    <td>${statusBadge(event.status)}</td>
    <td>${event.rules && event.rules.length ? `<span class="mono small">${event.rules[0].id}</span>
      <div class="cell-sub truncate" style="max-width:240px">${esc(event.rules[0].msg)}</div>` : '<span class="muted-2">—</span>'}</td>
  </tr>`;
}

function bindEventRows() {
  document.querySelectorAll('[data-event]').forEach((row) => {
    row.addEventListener('click', () => openEventDrawer(row.dataset.event));
  });
  document.querySelectorAll('[data-goto-rule]').forEach((row) => {
    row.addEventListener('click', () => {
      state.rules.q = row.dataset.gotoRule;
      state.rules.page = 1;
      window.location.hash = '#/rules';
    });
  });
}

async function openEventDrawer(uid) {
  const event = await api(`/api/events/${encodeURIComponent(uid)}`);
  const clientIp = String(event.ip || '').trim();
  const eventTarget = `${event.host || ''}${event.path || '/'}`;
  openDrawer({
    title: `Event ${event.method} ${event.path}`,
    subtitle: `${fmtDate(event.ts)} · ${esc(event.ip || 'IP tidak dikenal')}`,
    body: `
      <div class="row" style="margin-bottom:16px">
        ${actionBadge({ ...event, rules: event.rules })}
        ${statusBadge(event.status)}
        ${event.score ? `<span class="badge warning">Score ${event.score}</span>` : ''}
        ${event.phase ? `<span class="badge outline">Phase ${event.phase}</span>` : ''}
      </div>
      <dl class="kv">
        <dt>Client IP</dt><dd>${esc(event.ip || '—')}</dd>
        <dt>Request</dt><dd>${esc(event.method)} ${esc(event.uri || '/')}</dd>
        <dt>Host</dt><dd>${esc(event.host || '—')}</dd>
        <dt>HTTP status</dt><dd>${event.status || '—'}</dd>
        <dt>Unique ID</dt><dd>${esc(event.uniqueId || event.uid)}</dd>
        <dt>User-Agent</dt><dd>${esc(event.userAgent || '—')}</dd>
        <dt>${t('interrupted')}</dt><dd>${event.interrupted ? t('yes') : t('no')}</dd>
        <dt>Action message</dt><dd>${esc(event.actionMessage || '—')}</dd>
      </dl>
      <div class="divider"></div>
      <h3 style="font-size:13px;margin:0 0 10px">${t('triggeredRules')} (${event.rules.length})</h3>
      <div class="event-rules">
        ${
          event.rules.length
            ? event.rules
                .map(
                  (rule) => `<div class="event-rule">
                    <div class="id">${rule.id}</div>
                    <div>
                      <div class="msg">${esc(rule.msg)}</div>
                      <div class="row" style="margin-top:6px">${sevBadge(rule.severity)}
                        ${rule.data ? `<span class="cell-sub mono truncate" style="max-width:340px">${esc(rule.data)}</span>` : ''}
                      </div>
                    </div>
                  </div>`
                )
                .join('')
            : `<div class="muted small">${t('noTriggeredRules')}</div>`
        }
      </div>
      <div class="divider"></div>
      <div class="code-head">
        <span class="file-name">Raw audit event (JSON)</span>
        <button class="btn sm ghost" id="copyEvent" style="margin-left:auto">${icon('copy', 'sm')} Copy</button>
      </div>
      <pre class="code" id="eventRaw">${esc(JSON.stringify(event.raw, null, 2))}</pre>`,
    footer: `${event.rules?.length && event.host ? `<button class="btn" id="eventAllowPath">${icon('check', 'sm')} ${t('allowPath')}</button>` : ''}
      ${event.host ? `<button class="btn danger" id="eventBlockPath">${icon('shield', 'sm')} ${t('blockPath')}</button>` : ''}
      ${clientIp ? `<button class="btn" id="eventAllowIp">${icon('check', 'sm')} ${t('allowIp')}</button>
      <button class="btn danger" id="eventBlockIp">${icon('shield', 'sm')} ${t('blockIp')}</button>` : ''}`,
  });
  const copyBtn = document.getElementById('copyEvent');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => copyText(JSON.stringify(event.raw, null, 2)));
  }
  const applyIpAction = async (type) => {
    const isAllow = type === 'allow';
    const ok = await confirmDialog({
      title: t(isAllow ? 'allowIpTitle' : 'blockIpTitle'),
      message: `${t(isAllow ? 'allowIpConfirm' : 'blockIpConfirm')} ${clientIp}`,
      confirmLabel: t(isAllow ? 'allowIp' : 'blockIp'),
      danger: true,
    });
    if (!ok) return;
    const button = document.getElementById(isAllow ? 'eventAllowIp' : 'eventBlockIp');
    setBusy(button, true);
    try {
      await api('/api/ip-lists/quick-action', {
        method: 'POST',
        body: {
          type,
          value: clientIp,
          note: `Audit event ${event.uniqueId || event.uid}: ${event.method} ${event.uri || '/'}`,
        },
      });
      toast(t('ipActionApplied'), 'ok');
      closeDrawer();
      refreshChrome();
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  };
  document.getElementById('eventAllowIp')?.addEventListener('click', () => applyIpAction('allow'));
  document.getElementById('eventBlockIp')?.addEventListener('click', () => applyIpAction('block'));
  const applyPathAction = async (action) => {
    const isAllow = action === 'allow';
    const ok = await confirmDialog({
      title: t(isAllow ? 'allowPathTitle' : 'blockPathTitle'),
      message: `${t(isAllow ? 'allowPathConfirm' : 'blockPathConfirm')} ${eventTarget}`,
      confirmLabel: t(isAllow ? 'allowPath' : 'blockPath'),
      danger: !isAllow,
    });
    if (!ok) return;
    const button = document.getElementById(isAllow ? 'eventAllowPath' : 'eventBlockPath');
    setBusy(button, true);
    try {
      await api(`/api/events/${encodeURIComponent(event.uid)}/path-action`, {
        method: 'POST',
        body: { action },
      });
      toast(t('pathActionApplied'), 'ok');
      closeDrawer();
      refreshChrome();
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  };
  document.getElementById('eventAllowPath')?.addEventListener('click', () => applyPathAction('allow'));
  document.getElementById('eventBlockPath')?.addEventListener('click', () => applyPathAction('block'));
}

/* =========================================================================
   Audit events
   ========================================================================= */

async function renderEvents() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const filters = state.events;
  const params = new URLSearchParams({
    limit: String(filters.limit),
    offset: String(filters.offset),
    q: filters.q,
    action: filters.action,
    range: filters.range,
  });
  const data = await api(`/api/events?${params.toString()}`);
  const total = data.total || 0;
  const page = Math.floor((data.offset || 0) / (data.limit || filters.limit)) + 1;
  const pages = Math.max(1, Math.ceil(total / (data.limit || filters.limit)));
  if (filters.offset > 0 && !data.items?.length && total > 0) {
    filters.offset = Math.max(0, (pages - 1) * filters.limit);
    return renderEvents();
  }
  const start = total ? data.offset + 1 : 0;
  const end = Math.min(total, data.offset + (data.items || []).length);

  view.innerHTML = `
    ${pageHead(
      'Audit Events',
      t('eventsSub'),
      `<button class="btn sm" id="evtRefresh">${icon('refresh', 'sm')} ${t('refresh')}</button>`
    )}
    <div class="card">
      <div class="toolbar">
        <div class="search" style="min-width:250px;flex:1;max-width:380px">
          ${icon('search', 'sm')}
          <input id="evtSearch" type="search" placeholder="${t('searchEvents')}" value="${esc(filters.q)}" />
        </div>
        <select id="evtAction" style="width:auto;min-width:140px" aria-label="Filter aksi">
          <option value="" ${filters.action === '' ? 'selected' : ''}>${t('allActions')}</option>
          <option value="blocked" ${filters.action === 'blocked' ? 'selected' : ''}>Diblokir</option>
          <option value="detected" ${filters.action === 'detected' ? 'selected' : ''}>Terdeteksi</option>
          <option value="allowed" ${filters.action === 'allowed' ? 'selected' : ''}>Lolos</option>
        </select>
        <select id="evtRange" style="width:auto;min-width:140px" aria-label="Rentang waktu">
          <option value="1h" ${filters.range === '1h' ? 'selected' : ''}>1 jam terakhir</option>
          <option value="6h" ${filters.range === '6h' ? 'selected' : ''}>6 jam terakhir</option>
          <option value="24h" ${filters.range === '24h' ? 'selected' : ''}>24 jam terakhir</option>
          <option value="7d" ${filters.range === '7d' ? 'selected' : ''}>7 hari terakhir</option>
          <option value="all" ${filters.range === 'all' ? 'selected' : ''}>${t('allRanges')}</option>
        </select>
        <button class="btn sm" id="evtApply">${icon('filter', 'sm')} ${t('apply')}</button>
        <span class="spacer"></span>
        <span class="muted small">${fmtNum(total)} event</span>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead>
            <tr><th>${t('thTime')}</th><th>${t('thAction')}</th><th>${t('thIp')}</th><th>${t('thRequest')}</th><th>${t('thStatus')}</th><th>${t('thRule')}</th></tr>
          </thead>
          <tbody>
            ${
              (data.items || []).length
                ? data.items.map(eventRow).join('')
                : `<tr><td colspan="6">${emptyState('activity', t('noEvents'), t('noEventsFilter'))}</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div class="table-foot">
        <span>${start}–${end} ${t('of')} ${fmtNum(total)}</span>
        <span class="spacer"></span>
        <span class="muted small">${t('pageOf')} ${page} / ${pages}</span>
        <button class="btn sm" id="evtPrev" ${page <= 1 ? 'disabled' : ''}>${icon('chevron-left', 'sm')} ${t('prev')}</button>
        <button class="btn sm" id="evtNext" ${page >= pages ? 'disabled' : ''}>${t('next')} ${icon('chevron-right', 'sm')}</button>
      </div>
    </div>
    ${
      data.status?.error
        ? `<div class="note warn mt-16">${icon('alert')}<div>Audit log: ${esc(data.status.error)}<br />
            <span class="mono small">${esc(data.status.file)}</span></div></div>`
        : ''
    }`;

  bindEventRows();
  const refresh = () => renderEvents();
  document.getElementById('evtRefresh').addEventListener('click', refresh);
  document.getElementById('evtApply').addEventListener('click', () => {
    state.events.q = document.getElementById('evtSearch').value.trim();
    state.events.action = document.getElementById('evtAction').value;
    state.events.range = document.getElementById('evtRange').value;
    state.events.offset = 0;
    renderEvents();
  });
  document.getElementById('evtSearch').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') document.getElementById('evtApply').click();
  });
  document.getElementById('evtPrev').addEventListener('click', () => {
    state.events.offset = Math.max(0, state.events.offset - state.events.limit);
    renderEvents();
  });
  document.getElementById('evtNext').addEventListener('click', () => {
    state.events.offset += state.events.limit;
    renderEvents();
  });
}

/* =========================================================================
   CRS rules
   ========================================================================= */

async function renderRules() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const f = state.rules;
  const params = new URLSearchParams({
    page: String(f.page),
    limit: String(f.limit),
    q: f.q,
    severity: f.severity,
    status: f.status,
    pl: f.pl,
  });
  const data = await api(`/api/rules?${params.toString()}`);
  state.rules.page = data.page;

  view.innerHTML = `
    ${pageHead(
      'CRS Rules',
      `OWASP Core Rule Set ${esc(state.chrome?.crs?.version || '')} — ${fmtNum(data.counts.total)} ${t('rulesDetected')}.`,
      `<button class="btn sm" id="rulesFiles">${icon('file', 'sm')} ${t('viewFiles')}</button>
       <a class="btn sm" href="#/test">${icon('terminal', 'sm')} ${t('testRule')}</a>`
    )}
    <div class="note">${icon('info')}
      <div>Rule yang dinonaktifkan dari panel akan ditulis ke <span class="mono">REQUEST-905-OPENWAF-CUSTOM.conf</span>
      dan dibaca sebelum rule deteksi CRS. Exclusion global di halaman Exclusions juga tampil sebagai nonaktif di sini.</div>
    </div>
    <div class="card mt-16">
      <div class="toolbar">
        <div class="search" style="min-width:240px;flex:1;max-width:360px">
          ${icon('search', 'sm')}
          <input id="ruleSearch" type="search" placeholder="${t('searchRules')}" value="${esc(f.q)}" />
        </div>
        <select id="ruleSeverity" style="width:auto" aria-label="Severity">
          <option value="">${t('allSeverities')}</option>
          ${['CRITICAL', 'ERROR', 'WARNING', 'NOTICE']
            .map((sev) => `<option value="${sev}" ${f.severity === sev ? 'selected' : ''}>${sev}</option>`)
            .join('')}
        </select>
        <select id="ruleStatus" style="width:auto" aria-label="Status">
          <option value="">${t('allStatuses')}</option>
          <option value="enabled" ${f.status === 'enabled' ? 'selected' : ''}>${t('enabledOption')}</option>
          <option value="disabled" ${f.status === 'disabled' ? 'selected' : ''}>${t('disabledOption')}</option>
        </select>
        <select id="rulePl" style="width:auto" aria-label="Paranoia level">
          <option value="">${t('allPl')}</option>
          ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${String(f.pl) === String(pl) ? 'selected' : ''}>PL ${pl}</option>`).join('')}
        </select>
        <button class="btn sm" id="ruleApply">${icon('filter', 'sm')} ${t('apply')}</button>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead>
            <tr><th style="width:92px">ID</th><th>${t('thRule')}</th><th>${t('thSeverity')}</th><th>${t('thPl')}</th><th>${t('thPhase')}</th><th>${t('thFile')}</th><th style="width:70px;text-align:center">${t('thActive')}</th></tr>
          </thead>
          <tbody>
            ${
              data.items.length
                ? data.items
                    .map(
                      (rule) => `<tr class="clickable" data-rule-row="${rule.id}">
                        <td class="mono">${rule.id}</td>
                        <td>
                          <div class="rule-name">${esc(rule.msg)}</div>
                          <div class="cell-sub">${esc(rule.category)}${rule.tags?.length ? ` · ${esc(rule.tags.slice(0, 3).join(', '))}` : ''}</div>
                        </td>
                        <td>${sevBadge(rule.severity)}</td>
                        <td class="mono">${rule.paranoia || '—'}</td>
                        <td class="mono">${rule.phase || '—'}</td>
                        <td class="mono small truncate" style="max-width:190px">${esc(rule.file)}</td>
                        <td style="text-align:center" data-no-row-click>
                          <label class="switch" title="${rule.reason === 'excluded' ? t('disabledByGlobalExclusion') : rule.enabled ? t('enabledOption') : t('disabledOption')}">
                            <input type="checkbox" data-rule-toggle="${rule.id}" ${rule.enabled ? 'checked' : ''} ${rule.reason === 'excluded' ? 'disabled' : ''} />
                            <span class="track"></span>
                          </label>
                        </td>
                      </tr>`
                    )
                    .join('')
                : `<tr><td colspan="7">${emptyState('rules', t('noRulesFound'), t('noRulesMatch'))}</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div class="table-foot">
        <span>${fmtNum(data.counts.enabled)} ${t('enabledCount')} · ${fmtNum(data.counts.disabled)} ${t('disabledCount')}</span>
        <span class="spacer"></span>
        <span class="muted small">${t('pageOf')} ${data.page} / ${data.pages}</span>
        <button class="btn sm" id="rulesPrev" ${data.page <= 1 ? 'disabled' : ''}>${icon('chevron-left', 'sm')} ${t('prev')}</button>
        <button class="btn sm" id="rulesNext" ${data.page >= data.pages ? 'disabled' : ''}>${t('next')} ${icon('chevron-right', 'sm')}</button>
      </div>
    </div>`;

  document.getElementById('rulesFiles').addEventListener('click', () => openFilesDrawer('zzz'));
  document.getElementById('ruleApply').addEventListener('click', () => {
    state.rules.q = document.getElementById('ruleSearch').value.trim();
    state.rules.severity = document.getElementById('ruleSeverity').value;
    state.rules.status = document.getElementById('ruleStatus').value;
    state.rules.pl = document.getElementById('rulePl').value;
    state.rules.page = 1;
    renderRules();
  });
  document.getElementById('ruleSearch').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') document.getElementById('ruleApply').click();
  });
  ['ruleSeverity', 'ruleStatus', 'rulePl'].forEach((id) => {
    document.getElementById(id).addEventListener('change', () => document.getElementById('ruleApply').click());
  });
  document.getElementById('rulesPrev').addEventListener('click', () => {
    state.rules.page = Math.max(1, state.rules.page - 1);
    renderRules();
  });
  document.getElementById('rulesNext').addEventListener('click', () => {
    state.rules.page += 1;
    renderRules();
  });

  document.querySelectorAll('[data-rule-toggle]').forEach((checkbox) => {
    checkbox.addEventListener('change', async (event) => {
      event.stopPropagation();
      const id = Number(checkbox.dataset.ruleToggle);
      const enabled = checkbox.checked;
      checkbox.disabled = true;
      try {
        const result = await api('/api/rules/toggle', { method: 'POST', body: { ids: [id], enabled } });
        toast(`Rule ${id}: ${t(enabled ? 'ruleEnabled' : 'ruleDisabled')}`, 'ok');
        if (result.reload && result.reload.skipped) toast(t('reloadUnavailable'), 'info');
        refreshChrome();
        await renderRules();
      } catch (err) {
        checkbox.checked = !enabled;
        checkbox.disabled = false;
        showApiError(err);
      }
    });
  });

  document.querySelectorAll('[data-rule-row]').forEach((row) => {
    row.addEventListener('click', (event) => {
      if (event.target.closest('[data-no-row-click]')) return;
      openRuleDrawer(Number(row.dataset.ruleRow));
    });
  });
}

async function openRuleDrawer(id) {
  const rule = await api(`/api/rules/${id}`);
  openDrawer({
    title: `Rule ${rule.id}`,
    subtitle: `${esc(rule.category)} · PL ${rule.paranoia || '—'} · phase ${rule.phase || '—'}`,
    body: `
      <div class="row" style="margin-bottom:16px">
        ${sevBadge(rule.severity)}
        <span class="badge ${rule.enabled ? 'ok' : 'disabled'}">${t(rule.enabled ? 'enabledOption' : 'disabledOption')}</span>
        ${rule.reason === 'excluded' ? `<span class="badge violet">${t('globalExclusion')}</span>` : ''}
      </div>
      <h3 style="font-size:14px;line-height:1.5;margin:0 0 14px">${esc(rule.msg)}</h3>
      <dl class="kv">
        <dt>File</dt><dd class="mono">${esc(rule.file)}:${rule.line || '—'}</dd>
        <dt>Tag</dt><dd>${rule.tags?.length ? rule.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join(' ') : '—'}</dd>
      </dl>
      <div class="divider"></div>
      <div class="code-head"><span class="file-name">${t('ruleDefinition')}</span>
        <button class="btn sm ghost" id="copyRule" style="margin-left:auto">${icon('copy', 'sm')} ${t('copy')}</button>
      </div>
      <pre class="code" id="ruleRaw">${esc(rule.raw)}</pre>`,
    footer: rule.reason === 'excluded'
      ? `<span class="muted small">${t('disabledByExclusion')}</span>`
      : `<button class="btn ${rule.enabled ? 'danger' : 'primary'}" id="ruleToggleDrawer">${t(rule.enabled ? 'disableRule' : 'enableRule')}</button>`,
  });
  document.getElementById('copyRule').addEventListener('click', () => copyText(rule.raw));
  const toggle = document.getElementById('ruleToggleDrawer');
  if (toggle) {
    toggle.addEventListener('click', async () => {
      setBusy(toggle, true);
      try {
        await api('/api/rules/toggle', { method: 'POST', body: { ids: [rule.id], enabled: !rule.enabled } });
        toast(`Rule ${rule.id}: ${t(rule.enabled ? 'ruleDisabled' : 'ruleEnabled')}`, 'ok');
        closeDrawer();
        refreshChrome();
        renderRules();
      } catch (err) {
        showApiError(err);
        setBusy(toggle, false);
      }
    });
  }
}

/* =========================================================================
   Custom rules
   ========================================================================= */

const CUSTOM_FIELDS = [
  'REQUEST_URI',
  'REQUEST_FILENAME',
  'QUERY_STRING',
  'REQUEST_METHOD',
  'REQUEST_BODY',
  'ARGS',
  'ARGS_NAMES',
  'REQUEST_COOKIES',
  'REQUEST_HEADERS:User-Agent',
  'REQUEST_HEADERS:Host',
  'REQUEST_HEADERS:Referer',
  'REQUEST_HEADERS:X-Forwarded-For',
  'REMOTE_ADDR',
];

const CUSTOM_OPERATORS = [
  ['@rx', 'Regex (@rx)'],
  ['@contains', 'opContains'],
  ['@beginsWith', 'opBegins'],
  ['@endsWith', 'opEnds'],
  ['@eq', 'opEquals'],
  ['@ipMatch', 'IP match (@ipMatch)'],
  ['@pm', 'opKeywords'],
  ['@gt', 'opGreater'],
  ['@lt', 'opLess'],
];

const customOperatorLabel = (label) => label.startsWith('op') ? t(label) : label;

function previewCustomRule(values, id) {
  const phase = Number(values.phase) || 2;
  const status = Number(values.status) || 403;
  const action = ['deny', 'pass', 'allow'].includes(values.action) ? values.action : 'deny';
  const disruptiveActions = action === 'deny' ? `deny,status:${status},log` : `${action},log`;
  return `SecRule ${values.field || 'REQUEST_URI'} "${values.operator || '@rx'} ${
    values.pattern || '<pattern>'
  }" \\\n    "id:${id || '9001xxx'},phase:${phase},${disruptiveActions},msg:'${
    values.message || 'AsekWAF custom rule'
  }',severity:'${values.severity || 'CRITICAL'}',tag:'openwaf/custom',t:none"`;
}

async function renderCustomRules() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const data = await api('/api/custom-rules');
  const items = data.items || [];

  view.innerHTML = `
    ${pageHead(
      'Custom Rules',
      t('customSub'),
      `<button class="btn sm primary" id="newCustom">${icon('plus', 'sm')} ${t('newCustom')}</button>`
    )}
    <div class="note">${icon('info')}
      <div>Gunakan custom rule untuk kebutuhan spesifik aplikasi. ID dialokasikan otomatis pada mode
      <strong>Builder</strong>; mode <strong>Raw</strong> harus memakai ID 7 digit di rentang
      <span class="mono">9000000–9999999</span>.</div>
    </div>
    <div class="card mt-16">
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>ID</th><th>${t('thName')}</th><th>${t('thCondition')}</th><th>${t('thPhase')}</th><th>${t('thAction')}</th><th style="text-align:center">${t('thActive')}</th><th style="width:110px"></th></tr></thead>
          <tbody>
            ${
              items.length
                ? items
                    .map(
                      (rule) => `<tr>
                        <td class="mono">${rule.id}</td>
                        <td><div style="font-weight:600">${esc(rule.name)}</div>
                          <div class="cell-sub">${rule.mode === 'raw' ? 'Raw ModSecurity' : esc(rule.field)}</div></td>
                        <td class="mono small truncate" style="max-width:360px">${
                          rule.mode === 'raw' ? 'SecRule raw' : `${esc(rule.operator)} ${esc(rule.pattern)}`
                        }</td>
                        <td class="mono">${rule.phase}</td>
                        <td><span class="badge ${rule.action === 'allow' ? 'ok' : rule.action === 'pass' ? 'info' : 'critical'}">${esc(rule.action)}</span>
                          ${sevBadge(rule.severity)}</td>
                        <td style="text-align:center">
                          <label class="switch"><input type="checkbox" data-custom-toggle="${rule.id}" ${rule.enabled ? 'checked' : ''} />
                            <span class="track"></span></label>
                        </td>
                        <td>
                          <div class="row" style="gap:4px;justify-content:flex-end">
                            <button class="icon-btn" data-custom-code="${rule.id}" title="${t('viewCode')}">${icon('code', 'sm')}</button>
                            <button class="icon-btn" data-custom-edit="${rule.id}" title="${t('edit')}">${icon('edit', 'sm')}</button>
                            <button class="icon-btn danger" data-custom-delete="${rule.id}" title="${t('delete')}">${icon('trash', 'sm')}</button>
                          </div>
                        </td>
                      </tr>`
                    )
                    .join('')
                : `<tr><td colspan="7">${emptyState('code', t('noCustomFound'), t('noCustomSub'))}</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div class="table-foot"><span>${items.length} custom rule</span></div>
    </div>`;

  document.getElementById('newCustom').addEventListener('click', () => openCustomRuleModal(null));
  items.forEach((rule) => {
    document.querySelector(`[data-custom-code="${rule.id}"]`)?.addEventListener('click', () => {
      openDrawer({
        title: `Custom rule ${rule.id}`,
        subtitle: esc(rule.name),
        body: `<div class="code-head"><span class="file-name">${t('generatedRule')}</span>
            <button class="btn sm ghost" id="copyCustom" style="margin-left:auto">${icon('copy', 'sm')} ${t('copy')}</button></div>
          <pre class="code">${esc(rule.raw)}</pre>
          ${rule.note ? `<div class="note">${icon('info')}<div>${esc(rule.note)}</div></div>` : ''}`,
      });
      document.getElementById('copyCustom').addEventListener('click', () => copyText(rule.raw));
    });
    document.querySelector(`[data-custom-edit="${rule.id}"]`)?.addEventListener('click', () => openCustomRuleModal(rule));
    document.querySelector(`[data-custom-delete="${rule.id}"]`)?.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: t('deleteCustomTitle'),
        message: `${t('deleteCustomConfirm')} "${rule.name}" (${rule.id}).`,
        confirmLabel: t('deleteRule'),
      });
      if (!ok) return;
      try {
        await api(`/api/custom-rules/${rule.id}`, { method: 'DELETE' });
        toast(t('customDeleted'), 'ok');
        refreshChrome();
        renderCustomRules();
      } catch (err) {
        showApiError(err);
      }
    });
    document.querySelector(`[data-custom-toggle="${rule.id}"]`)?.addEventListener('change', async (event) => {
      const checkbox = event.currentTarget;
      const enabled = checkbox.checked;
      checkbox.disabled = true;
      try {
        await api(`/api/custom-rules/${rule.id}`, { method: 'PUT', body: { enabled } });
        toast(t(enabled ? 'customEnabled' : 'customDisabled'), 'ok');
        checkbox.disabled = false;
      } catch (err) {
        checkbox.checked = !enabled;
        checkbox.disabled = false;
        showApiError(err);
      }
    });
  });
}

function openCustomRuleModal(rule) {
  const isRaw = rule?.mode === 'raw';
  const values = {
    name: rule?.name || '',
    field: rule?.field || 'REQUEST_URI',
    operator: rule?.operator || '@rx',
    pattern: rule?.pattern || '',
    action: rule?.action || 'deny',
    status: rule?.status || 403,
    phase: rule?.phase || 2,
    severity: rule?.severity || 'CRITICAL',
    message: rule?.message || '',
    note: rule?.note || '',
    enabled: rule?.enabled !== false,
  };
  const rawValue = rule?.raw || '';
  let mode = isRaw ? 'raw' : 'builder';

  openModal({
    wide: true,
    title: rule ? `${t('editCustomTitle')} ${rule.id}` : t('newCustomTitle'),
    body: `<form id="customRuleForm" class="form-grid" novalidate>
      <div class="segmented" id="customMode" role="tablist">
        <button type="button" data-mode="builder" class="${mode === 'builder' ? 'active' : ''}">Builder</button>
        <button type="button" data-mode="raw" class="${mode === 'raw' ? 'active' : ''}">Raw ModSecurity</button>
      </div>
      <div id="builderPane" class="form-grid cols-2" ${mode === 'raw' ? 'hidden' : ''}>
        <div class="field span-2">
          <label for="crName">${t('ruleName')}</label>
          <input id="crName" type="text" maxlength="120" placeholder="${t('ruleNameExample')}" value="${esc(values.name)}" />
        </div>
        <div class="field">
          <label for="crField">${t('fieldVariable')}</label>
          <select id="crField">${CUSTOM_FIELDS.map((field) => `<option value="${field}" ${values.field === field ? 'selected' : ''}>${field}</option>`).join('')}</select>
        </div>
        <div class="field">
          <label for="crOperator">${t('operator')}</label>
          <select id="crOperator">${CUSTOM_OPERATORS.map(([value, label]) => `<option value="${value}" ${values.operator === value ? 'selected' : ''}>${customOperatorLabel(label)}</option>`).join('')}</select>
        </div>
        <div class="field span-2">
          <label for="crPattern">Pattern</label>
          <input id="crPattern" type="text" placeholder="${t('patternExample')}" value="${esc(values.pattern)}" />
          <span class="hint">${t('patternHint')}</span>
        </div>
        <div class="field">
          <label for="crAction">${t('actionLabel')}</label>
          <select id="crAction">
            <option value="deny" ${values.action === 'deny' ? 'selected' : ''}>${t('denyAction')}</option>
            <option value="pass" ${values.action === 'pass' ? 'selected' : ''}>${t('passAction')}</option>
            <option value="allow" ${values.action === 'allow' ? 'selected' : ''}>${t('allowAction')}</option>
          </select>
          <span class="hint">${t('allowWarning')}</span>
        </div>
        <div class="field">
          <label for="crStatus">HTTP status (deny)</label>
          <input id="crStatus" type="number" min="100" max="599" value="${values.status}" />
        </div>
        <div class="field">
          <label for="crPhase">Phase</label>
          <select id="crPhase">${[1, 2, 3, 4, 5].map((phase) => `<option value="${phase}" ${Number(values.phase) === phase ? 'selected' : ''}>Phase ${phase}</option>`).join('')}</select>
        </div>
        <div class="field">
          <label for="crSeverity">Severity</label>
          <select id="crSeverity">${['CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFO'].map((sev) => `<option value="${sev}" ${values.severity === sev ? 'selected' : ''}>${sev}</option>`).join('')}</select>
        </div>
        <div class="field span-2">
          <label for="crMessage">${t('logMessage')}</label>
          <input id="crMessage" type="text" maxlength="200" placeholder="${t('logMessageHint')}" value="${esc(values.message)}" />
        </div>
      </div>
      <div id="rawPane" ${mode === 'raw' ? '' : 'hidden'}>
        <div class="field">
          <label for="crRaw">Raw ModSecurity rule</label>
          <textarea id="crRaw" rows="8" spellcheck="false" placeholder="SecRule REQUEST_URI &quot;@contains /secret&quot; \\&#10;    &quot;id:9001234,phase:1,deny,status:403,log,msg:'Block secret',severity:'CRITICAL',tag:'openwaf/custom',t:none&quot;">${esc(rawValue)}</textarea>
          <span class="hint">${t('rawRuleHint')}</span>
        </div>
      </div>
      <div class="field">
        <label for="crNote">${t('optionalNote')}</label>
        <input id="crNote" type="text" maxlength="300" value="${esc(values.note)}" placeholder="${t('noteHint')}" />
      </div>
      <label class="switch-row">
        <span><span class="switch-label">${t('enableRule')}</span><span class="hint">${t('ruleAppliedHint')}</span></span>
        <span class="switch"><input id="crEnabled" type="checkbox" ${values.enabled ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <div class="code-head"><span class="file-name">${t('preview')}</span></div>
      <pre class="code" id="customPreview">${esc(rawValue || previewCustomRule(values, rule?.id))}</pre>
    </form>`,
    footer: `<button class="btn" data-close>${t('cancel')}</button>
      <button class="btn primary" id="saveCustom">${t(rule ? 'saveChanges' : 'createRule')}</button>`,
  });

  const modal = modalRoot.querySelector('.modal');
  const builderPane = document.getElementById('builderPane');
  const rawPane = document.getElementById('rawPane');
  const preview = document.getElementById('customPreview');

  const readBuilder = () => ({
    name: document.getElementById('crName').value.trim(),
    field: document.getElementById('crField').value,
    operator: document.getElementById('crOperator').value,
    pattern: document.getElementById('crPattern').value,
    action: document.getElementById('crAction').value,
    status: Number(document.getElementById('crStatus').value) || 403,
    phase: Number(document.getElementById('crPhase').value) || 2,
    severity: document.getElementById('crSeverity').value,
    message: document.getElementById('crMessage').value.trim(),
    note: document.getElementById('crNote').value.trim(),
    enabled: document.getElementById('crEnabled').checked,
  });

  const updatePreview = () => {
    document.getElementById('crStatus').disabled = document.getElementById('crAction').value !== 'deny';
    if (mode === 'raw') {
      preview.textContent = document.getElementById('crRaw').value || t('startRawRule');
    } else {
      preview.textContent = previewCustomRule(readBuilder(), rule?.id);
    }
  };

  modal.querySelectorAll('#customMode [data-mode]').forEach((button) => {
    button.addEventListener('click', () => {
      mode = button.dataset.mode;
      modal.querySelectorAll('#customMode [data-mode]').forEach((el) => el.classList.toggle('active', el === button));
      builderPane.hidden = mode !== 'builder';
      rawPane.hidden = mode !== 'raw';
      updatePreview();
    });
  });
  modal.querySelectorAll('input, select, textarea').forEach((el) => {
    el.addEventListener('input', updatePreview);
    el.addEventListener('change', updatePreview);
  });

  document.getElementById('saveCustom').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    let body;
    if (mode === 'raw') {
      body = {
        mode: 'raw',
        raw: document.getElementById('crRaw').value,
        name: readBuilder().name || `Raw rule ${rule?.id || ''}`.trim(),
        note: readBuilder().note,
        enabled: document.getElementById('crEnabled').checked,
      };
      if (!body.raw.trim()) {
        toast(t('rawRuleEmpty'), 'error');
        return;
      }
    } else {
      body = { ...readBuilder(), mode: 'builder' };
      if (!body.pattern.trim()) {
        toast(t('requiredPattern'), 'error');
        document.getElementById('crPattern').focus();
        return;
      }
      if (!body.name) body.name = `Custom rule ${rule?.id || ''}`.trim();
    }
    setBusy(button, true);
    try {
      if (rule) await api(`/api/custom-rules/${rule.id}`, { method: 'PUT', body });
      else await api('/api/custom-rules', { method: 'POST', body });
      closeModal();
      toast(t(rule ? 'customUpdated' : 'customCreated'), 'ok');
      refreshChrome();
      await renderCustomRules();
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  });
}

/* =========================================================================
   Exclusions
   ========================================================================= */

async function renderExclusions() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const data = await api('/api/exclusions');
  const items = data.items || [];

  view.innerHTML = `
    ${pageHead(
      'Exclusions',
      t('exclusionsSub'),
      `<button class="btn sm primary" id="newExclusion">${icon('plus', 'sm')} ${t('newExclusion')}</button>`
    )}
    <div class="note warn">${icon('alert')}
      <div><strong>${t('exclusionRecommended')}</strong> ${t('exclusionVsAllow')}</div>
    </div>
    <div class="card mt-16">
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>${t('thScope')}</th><th>${t('thTarget')}</th><th>${t('thRuleId')}</th><th>${t('thNote')}</th><th style="text-align:center">${t('thActive')}</th><th style="width:100px"></th></tr></thead>
          <tbody>
            ${
              items.length
                ? items
                    .map(
                      (item) => `<tr>
                        <td><span class="badge ${item.scope === 'global' ? 'violet' : 'info'}">${esc(item.scope)}</span></td>
                        <td class="mono small">${esc(item.scope === 'host_path' ? `${item.host}${item.match}` : (item.match || localizedLegacyText('semua trafik')))}</td>
                        <td>${(item.ruleIds || []).map((id) => `<span class="chip">${id}</span>`).join(' ')}</td>
                        <td class="muted small">${esc(item.note || '—')}</td>
                        <td style="text-align:center">
                          <label class="switch"><input type="checkbox" data-exc-toggle="${item.id}" ${item.enabled ? 'checked' : ''} />
                            <span class="track"></span></label>
                        </td>
                        <td>
                          <div class="row" style="gap:4px;justify-content:flex-end">
                            <button class="icon-btn" data-exc-edit="${item.id}" title="Edit">${icon('edit', 'sm')}</button>
                            <button class="icon-btn danger" data-exc-delete="${item.id}" title="${t('delete')}">${icon('trash', 'sm')}</button>
                          </div>
                        </td>
                      </tr>`
                    )
                    .join('')
                : `<tr><td colspan="6">${emptyState('filter', t('noExclFound'), t('noExclSub'))}</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div class="table-foot"><span>${items.length} exclusion</span></div>
    </div>`;

  document.getElementById('newExclusion').addEventListener('click', () => openExclusionModal(null));
  items.forEach((item) => {
    document.querySelector(`[data-exc-edit="${item.id}"]`)?.addEventListener('click', () => openExclusionModal(item));
    document.querySelector(`[data-exc-delete="${item.id}"]`)?.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: localizedLegacyText('Hapus exclusion?'),
        message: 'Rule yang dikecualikan akan aktif kembali setelah WAF di-reload.',
        confirmLabel: localizedLegacyText('Hapus exclusion'),
      });
      if (!ok) return;
      try {
        await api(`/api/exclusions/${item.id}`, { method: 'DELETE' });
        toast(t('exclusionDeleted'), 'ok');
        refreshChrome();
        renderExclusions();
      } catch (err) {
        showApiError(err);
      }
    });
    document.querySelector(`[data-exc-toggle="${item.id}"]`)?.addEventListener('change', async (event) => {
      const checkbox = event.currentTarget;
      const enabled = checkbox.checked;
      checkbox.disabled = true;
      try {
        await api(`/api/exclusions/${item.id}`, { method: 'PUT', body: { enabled } });
        toast(`${t('exclusions')}: ${t(enabled ? 'enabledOption' : 'disabledOption')}.`, 'ok');
        refreshChrome();
        checkbox.disabled = false;
      } catch (err) {
        checkbox.checked = !enabled;
        checkbox.disabled = false;
        showApiError(err);
      }
    });
  });
}

function openExclusionModal(item) {
  openModal({
    title: item ? 'Edit exclusion' : 'Exclusion baru',
    body: `<form id="excForm" class="form-grid cols-2">
      <div class="field">
        <label for="excScope">Scope</label>
        <select id="excScope">
          <option value="path" ${!item || item.scope === 'path' ? 'selected' : ''}>Path (prefix URI)</option>
          <option value="host" ${item?.scope === 'host' ? 'selected' : ''}>Host</option>
          <option value="host_path" ${item?.scope === 'host_path' ? 'selected' : ''}>Host + exact path</option>
          <option value="global" ${item?.scope === 'global' ? 'selected' : ''}>${localizedLegacyText('Global (semua trafik)')}</option>
        </select>
      </div>
      <div class="field" id="excMatchField">
        <label for="excMatch">Path / Host</label>
        <input id="excMatch" type="text" placeholder="/api/public atau app.example.com" value="${esc(item?.match || '')}" />
      </div>
      <div class="field span-2" id="excHostField" hidden>
        <label for="excHost">Exact host</label>
        <input id="excHost" type="text" placeholder="app.example.com" value="${esc(item?.host || '')}" />
      </div>
      <div class="field span-2">
        <label for="excRules">Rule ID yang dikecualikan</label>
        <input id="excRules" type="text" placeholder="942100, 942110, 949110" value="${esc((item?.ruleIds || []).join(', '))}" />
        <span class="hint">${localizedLegacyText('Pisahkan dengan koma. Gunakan ID rule CRS (6 digit).')}</span>
      </div>
      <div class="field span-2">
        <label for="excNote">${localizedLegacyText('Catatan')}</label>
        <input id="excNote" type="text" maxlength="300" value="${esc(item?.note || '')}" placeholder="${preferences.language === 'id' ? 'Alasan pengecualian, tiket, atau pemilik aplikasi' : 'Exclusion reason, ticket, or application owner'}" />
      </div>
      <label class="switch-row span-2">
        <span><span class="switch-label">Aktifkan exclusion</span></span>
        <span class="switch"><input id="excEnabled" type="checkbox" ${item?.enabled !== false ? 'checked' : ''} /><span class="track"></span></span>
      </label>
    </form>`,
    footer: `<button class="btn" data-close>${t('cancel')}</button>
      <button class="btn primary" id="saveExclusion">${item ? t('save') : localizedLegacyText('Buat exclusion')}</button>`,
  });

  const scope = document.getElementById('excScope');
  const matchField = document.getElementById('excMatchField');
  const hostField = document.getElementById('excHostField');
  const syncScope = () => {
    matchField.hidden = scope.value === 'global';
    hostField.hidden = scope.value !== 'host_path';
    document.getElementById('excMatch').placeholder =
      scope.value === 'host' ? 'app.example.com' : scope.value === 'host_path' ? '/api/public' : '/api/public';
  };
  scope.addEventListener('change', syncScope);
  syncScope();

  document.getElementById('saveExclusion').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const body = {
      scope: scope.value,
      match: document.getElementById('excMatch').value.trim(),
      host: document.getElementById('excHost').value.trim(),
      ruleIds: document.getElementById('excRules').value,
      note: document.getElementById('excNote').value.trim(),
      enabled: document.getElementById('excEnabled').checked,
    };
    if (!body.ruleIds.trim()) {
      toast('Minimal satu rule ID harus diisi.', 'error');
      return;
    }
    setBusy(button, true);
    try {
      if (item) await api(`/api/exclusions/${item.id}`, { method: 'PUT', body });
      else await api('/api/exclusions', { method: 'POST', body });
      closeModal();
      toast(t(item ? 'exclusionUpdated' : 'exclusionCreated'), 'ok');
      refreshChrome();
      await renderExclusions();
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  });
}

/* =========================================================================
   IP lists
   ========================================================================= */

async function renderIpLists() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const data = await api('/api/ip-lists');

  const listCard = (type, title, description, entries, tone) => `
    <div class="card">
      <div class="card-head">
        <div><h3>${title}</h3><div class="sub">${description}</div></div>
        <span class="badge ${tone}">${fmtNum(entries.length)} ${t('entries')}</span>
      </div>
      <div class="card-body" style="padding-top:0">
        <form data-ip-form="${type}" class="row" style="align-items:flex-end;gap:8px;flex-wrap:wrap;margin-bottom:14px">
          <div class="field" style="flex:1;min-width:160px">
            <label for="ip-${type}">IP / CIDR</label>
            <input id="ip-${type}" name="value" type="text" placeholder="203.0.113.7 atau 10.0.0.0/8" autocomplete="off" />
          </div>
          <div class="field" style="flex:1;min-width:150px">
            <label for="note-${type}">${localizedLegacyText('Catatan')}</label>
            <input id="note-${type}" name="note" type="text" maxlength="200" placeholder="opsional" />
          </div>
          <button class="btn sm primary" type="submit">${icon('plus', 'sm')} ${t('add')}</button>
        </form>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>IP / CIDR</th><th>${t('thNote')}</th><th style="width:54px"></th></tr></thead>
            <tbody>
              ${
                entries.length
                  ? entries
                      .map(
                        (entry) => `<tr>
                          <td class="mono">${esc(entry.value)}</td>
                          <td class="muted small">${esc(entry.note || '—')}</td>
                          <td><button class="icon-btn danger" data-ip-delete="${entry.id}" title="${t('delete')}">${icon('trash', 'sm')}</button></td>
                        </tr>`
                      )
                      .join('')
                  : `<tr><td colspan="3"><div class="muted small" style="padding:14px 4px">${t('noEntries')}</div></td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>`;

  view.innerHTML = `
    ${pageHead(
      'IP Lists',
      t('ipListsSub')
    )}
    <div class="note">${icon('info')}
      <div>Gunakan CIDR untuk rentang, contoh <span class="mono">10.0.0.0/8</span>. Perubahan langsung
      dibuat sebagai rule ModSecurity dan WAF di-reload. Pastikan IP panel manajemen tidak ikut diblokir.</div>
    </div>
    <div class="grid grid-2 mt-16">
      ${listCard('allow', 'Allowlist', t('allowlistHint'), data.allow || [], 'ok')}
      ${listCard('block', 'Blocklist', 'Selalu diblokir sebelum rule deteksi CRS dievaluasi.', data.block || [], 'critical')}
    </div>`;

  document.querySelectorAll('[data-ip-form]').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const type = form.dataset.ipForm;
      const value = form.querySelector('[name="value"]').value.trim();
      const note = form.querySelector('[name="note"]').value.trim();
      if (!value) {
        toast(t('requiredIp'), 'error');
        return;
      }
      const button = form.querySelector('button[type="submit"]');
      setBusy(button, true);
      try {
        await api('/api/ip-lists', { method: 'POST', body: { type, value, note } });
        toast(t('ipAdded'), 'ok');
        refreshChrome();
        await renderIpLists();
      } catch (err) {
        setBusy(button, false);
        showApiError(err);
      }
    });
  });

  document.querySelectorAll('[data-ip-delete]').forEach((button) => {
    button.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: localizedLegacyText('Hapus entri IP?'),
        message: localizedLegacyText('Entri akan dihapus dan WAF di-reload.'),
        confirmLabel: t('delete'),
      });
      if (!ok) return;
      try {
        await api(`/api/ip-lists/${button.dataset.ipDelete}`, { method: 'DELETE' });
        toast(t('ipDeleted'), 'ok');
        refreshChrome();
        await renderIpLists();
      } catch (err) {
        showApiError(err);
      }
    });
  });
}

/* =========================================================================
   Reverse proxy
   ========================================================================= */

async function renderProxy() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const data = await api('/api/proxy');
  const sites = data.sites || [];

  view.innerHTML = `
    ${pageHead(
      'Reverse Proxy',
      t('proxySub'),
      `<button class="btn sm" id="checkProxy">${icon('activity', 'sm')} ${t('checkProxy')}</button>
       <button class="btn sm primary" id="newSite">${icon('plus', 'sm')} ${t('newSite')}</button>`
    )}
    <div class="note">${icon('info')}
      <div>Gunakan port <span class="mono">8080</span> untuk routing hostname, atau pilih port publik
      apa pun dari <span class="mono">1–65535</span> untuk akses langsung melalui IP AsekWAF.
      Semua listener situs tetap melewati WAF.</div>
    </div>

    <div class="grid grid-2 mt-16">
      <div class="card">
        <div class="card-head">
          <div><h3>Upstream default</h3><div class="sub">Untuk request yang tidak cocok dengan situs mana pun</div></div>
          <span class="badge ${data.fallbackMode === 'return404' ? 'ok' : 'info'}">${data.fallbackMode === 'return404' ? 'HTTP 404' : esc(data.defaultUpstream)}</span>
        </div>
        <div class="card-body">
          <form id="defaultUpstreamForm" class="form-grid">
            <div class="field">
              <label for="fallbackMode">${t('fallbackBehavior')}</label>
              <select id="fallbackMode">
                <option value="return404" ${data.fallbackMode === 'return404' ? 'selected' : ''}>${t('return404')}</option>
                <option value="forward" ${data.fallbackMode !== 'return404' ? 'selected' : ''}>${t('forwardDefault')}</option>
              </select>
              <span class="hint" id="fallbackHint"></span>
            </div>
            <div class="field" id="defaultUpstreamField">
              <label for="defaultUpstream">URL upstream</label>
              <input id="defaultUpstream" type="text" value="${esc(data.defaultUpstream)}" placeholder="http://app:3000" />
              <span class="hint">${t('upstreamHint')} <span class="mono">http://192.168.1.20:3000</span>.</span>
            </div>
            <label class="switch-row" id="defaultPreserveHostRow">
              <span><span class="switch-label">Pertahankan Host header</span>
                <span class="hint">Kirim hostname asli ke upstream (berguna untuk virtual host aplikasi).</span></span>
              <span class="switch"><input id="defaultPreserveHost" type="checkbox" ${data.defaultPreserveHost !== false ? 'checked' : ''} /><span class="track"></span></span>
            </label>
            <div class="row">
              <button class="btn primary" type="submit" id="saveDefaultUpstream">${icon('save', 'sm')} ${t('saveUpstream')}</button>
            </div>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><div><h3>${t('howItWorks')}</h3><div class="sub">${t('routingSecurity')}</div></div></div>
        <div class="card-body">
          <div class="status-panel">
            <div class="status-item"><span class="label">Port HTTP</span><span class="value mono">8080</span></div>
            <div class="status-item"><span class="label">Port HTTPS</span><span class="value mono">8443</span></div>
            <div class="status-item"><span class="label">Fallback</span><span class="value">${data.fallbackMode === 'return404' ? t('return404') : t('forwardDefault')}</span></div>
            <div class="status-item"><span class="label">Default upstream</span><span class="value mono">${data.fallbackMode === 'return404' ? '—' : esc(data.defaultUpstream)}</span></div>
            <div class="status-item"><span class="label">Virtual host</span><span class="value">${sites.length} (${sites.filter((s) => s.enabled).length} aktif)</span></div>
            <div class="status-item"><span class="label">ModSecurity engine</span><span class="value">${esc(data.wafEngine)}</span></div>
            <div class="status-item"><span class="label">${t('protectedSites')}</span><span class="value">${data.wafProtectedSites} ${t('of')} ${sites.filter((s) => s.enabled).length} ${t('sites')}</span></div>
          </div>
          <div class="note mt-16">${icon('shield')}
            <div>Untuk HTTPS dengan sertifikat publik, terminasi TLS di load balancer / reverse proxy depan,
            lalu teruskan trafik ke port 8080. Sertifikat default image hanya untuk pengujian.</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card mt-16">
      <div class="card-head">
        <div><h3>${t('virtualHost')}</h3><div class="sub">${t('hostnameRouting')}</div></div>
        <span class="badge outline">${sites.length} ${t('sites')}</span>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>${t('thName')} / Host</th><th>${t('thPort')}</th><th>${t('thUpstream')}</th><th>${t('thWaf')}</th><th style="text-align:center">${t('thActive')}</th><th style="width:100px"></th></tr></thead>
          <tbody>
            ${
              sites.length
                ? sites
                    .map(
                      (site) => `<tr>
                        <td>
                          <div style="font-weight:600">${esc(site.name)}</div>
                          <div class="chip-list" style="margin-top:5px">${site.hosts.map((host) => `<span class="chip">${esc(host)}</span>`).join('')}</div>
                          ${site.note ? `<div class="cell-sub" style="margin-top:4px">${esc(site.note)}</div>` : ''}
                        </td>
                        <td><span class="badge info mono">${site.tls?.enabled ? 'https' : 'http'} :${site.listenPort || 8080}</span></td>
                        <td class="mono small">${esc(site.upstream)}
                          <div class="cell-sub">${site.websocket ? 'WebSocket aktif' : 'tanpa WebSocket'}${site.verifyTls ? ' · verifikasi TLS' : ''}</div>
                        </td>
                        <td><span class="badge ${site.wafEnabled && data.wafEngine !== 'Off' ? (data.wafEngine === 'On' ? 'ok' : 'warning') : 'disabled'}">${!site.wafEnabled ? t('disabledOption') : data.wafEngine === 'Off' ? 'Engine Off' : data.wafEngine}</span></td>
                        <td style="text-align:center">
                          <label class="switch"><input type="checkbox" data-site-toggle="${site.id}" ${site.enabled ? 'checked' : ''} />
                            <span class="track"></span></label>
                        </td>
                        <td>
                          <div class="row" style="gap:4px;justify-content:flex-end">
                            <button class="icon-btn" data-site-edit="${site.id}" title="Edit">${icon('edit', 'sm')}</button>
                            <button class="icon-btn danger" data-site-delete="${site.id}" title="${t('delete')}">${icon('trash', 'sm')}</button>
                          </div>
                        </td>
                      </tr>`
                    )
                    .join('')
                : `<tr><td colspan="6">${emptyState('network', t('noSitesFound'), t('noSitesSub'))}</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div class="table-foot">
        <span class="mono small">${esc(data.generatedFile || 'sites.conf')}</span>
        <span class="spacer"></span>
        <span class="muted small">Perubahan langsung di-reload ke Nginx</span>
      </div>
    </div>`;

  document.getElementById('newSite').addEventListener('click', () => openSiteModal(null, sites));
  const fallbackMode = document.getElementById('fallbackMode');
  const syncFallbackMode = () => {
    const forwarding = fallbackMode.value === 'forward';
    document.getElementById('defaultUpstreamField').hidden = !forwarding;
    document.getElementById('defaultPreserveHostRow').hidden = !forwarding;
    document.getElementById('fallbackHint').textContent = t(forwarding ? 'fallbackForwardHint' : 'fallback404Hint');
  };
  fallbackMode.addEventListener('change', syncFallbackMode);
  syncFallbackMode();
  document.getElementById('checkProxy').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, 'Memeriksa…');
    try {
      const result = await api('/api/proxy/diagnostics', { method: 'POST' });
      const failed = result.checks.filter((check) => !check.ok);
      openModal({
        title: 'Diagnostik reverse proxy',
        body: `<div class="status-panel">
          <div class="status-item"><span class="label">WAF engine</span><span class="value">${esc(result.engineMode)}</span></div>
          ${result.checks.map((check) => `<div class="status-item"><span class="label">${esc(check.name)}${check.host ? ` · ${esc(check.host)}` : ''}</span><span class="value">${check.ok ? `HTTP ${check.status}` : esc(check.error || 'gagal')}</span></div>`).join('')}
        </div><div class="note mt-16">${icon('info')}<div>${esc(result.note)}</div></div>`,
        footer: `<button class="btn" data-close>${t('close')}</button><a class="btn primary" href="#/test" data-close>${icon('terminal', 'sm')} ${t('test')}</a>`,
      });
      toast(failed.length ? `${failed.length} pemeriksaan proxy gagal.` : 'Listener dan routing Host dapat dijangkau.', failed.length ? 'error' : 'ok');
    } catch (err) {
      showApiError(err);
    } finally {
      setBusy(button, false);
    }
  });
  document.getElementById('saveDefaultUpstream').addEventListener('click', async (event) => {
    event.preventDefault();
    const button = event.currentTarget;
    const upstream = document.getElementById('defaultUpstream').value.trim();
    setBusy(button, true);
    try {
      await api('/api/proxy/default', {
        method: 'PUT',
        body: { mode: fallbackMode.value, upstream, preserveHost: document.getElementById('defaultPreserveHost').checked },
      });
      toast(t(fallbackMode.value === 'return404' ? 'fallbackApplied' : 'upstreamSaved'), 'ok');
      refreshChrome();
      await renderProxy();
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  });

  sites.forEach((site) => {
    document.querySelector(`[data-site-edit="${site.id}"]`)?.addEventListener('click', () => openSiteModal(site, sites));
    document.querySelector(`[data-site-delete="${site.id}"]`)?.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: localizedLegacyText('Hapus virtual host?'),
        message: `Situs "${site.name}" (${site.hosts.join(', ')}) akan dihapus dari konfigurasi Nginx.`,
        confirmLabel: localizedLegacyText('Hapus situs'),
      });
      if (!ok) return;
      try {
        await api(`/api/proxy/sites/${site.id}`, { method: 'DELETE' });
        toast(t('siteDeleted'), 'ok');
        refreshChrome();
        await renderProxy();
      } catch (err) {
        showApiError(err);
      }
    });
    document.querySelector(`[data-site-toggle="${site.id}"]`)?.addEventListener('change', async (event) => {
      const checkbox = event.currentTarget;
      const enabled = checkbox.checked;
      checkbox.disabled = true;
      try {
        await api(`/api/proxy/sites/${site.id}`, { method: 'PUT', body: { enabled } });
        toast(`${site.name}: ${t(enabled ? 'enabledOption' : 'disabledOption')}.`, 'ok');
        refreshChrome();
        checkbox.disabled = false;
      } catch (err) {
        checkbox.checked = !enabled;
        checkbox.disabled = false;
        showApiError(err);
      }
    });
  });
}

function openSiteModal(site, sites) {
  openModal({
    wide: true,
    title: site ? `${t('edit')} ${site.name}` : localizedLegacyText('Virtual host baru'),
    body: `<form id="siteForm" class="form-grid cols-2">
      <div class="field">
        <label for="siteName">${localizedLegacyText('Nama situs')}</label>
        <input id="siteName" type="text" maxlength="120" value="${esc(site?.name || '')}" placeholder="Aplikasi internal" />
      </div>
      <div class="field">
        <label for="siteListenPort">Port publik AsekWAF</label>
        <input id="siteListenPort" type="number" min="1" max="65535" value="${esc(site?.listenPort || 8080)}" placeholder="6677" />
        <span class="hint">Port akses pada IP server, misalnya <span class="mono">6677</span>.</span>
      </div>
      <div class="field span-2">
        <label for="siteUpstream">Upstream</label>
        <input id="siteUpstream" type="text" value="${esc(site?.upstream || '')}" placeholder="http://app:3000" />
        <span class="hint">Tanpa path. Gunakan https:// bila upstream TLS.</span>
      </div>
      <div class="field span-2">
        <label for="siteHosts">Hostname</label>
        <input id="siteHosts" type="text" value="${esc((site?.hosts || []).join(', '))}" placeholder="* atau app.example.com" />
        <span class="hint">Gunakan <span class="mono">*</span> untuk semua hostname, atau pisahkan beberapa hostname dengan koma.</span>
      </div>
      <div class="note span-2">${icon('info')}
        <div><span class="mono">8080</span> digunakan untuk routing hostname standar. Port <span class="mono">8081</span>,
        <span class="mono">8443</span>, dan <span class="mono">18080</span> dicadangkan AsekWAF.</div>
      </div>
      <label class="switch-row">
        <span><span class="switch-label">Pertahankan Host header</span>
          <span class="hint">Kirim hostname asli ke aplikasi.</span></span>
        <span class="switch"><input id="sitePreserveHost" type="checkbox" ${site?.preserveHost !== false ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <label class="switch-row">
        <span><span class="switch-label">WebSocket</span>
          <span class="hint">Aktifkan Upgrade/Connection header.</span></span>
        <span class="switch"><input id="siteWebsocket" type="checkbox" ${site?.websocket !== false ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <label class="switch-row">
        <span><span class="switch-label">Proteksi WAF</span>
          <span class="hint">Nonaktifkan hanya bila benar-benar diperlukan.</span></span>
        <span class="switch"><input id="siteWaf" type="checkbox" ${site?.wafEnabled !== false ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <label class="switch-row">
        <span><span class="switch-label">Verifikasi TLS upstream</span>
          <span class="hint">Hanya untuk upstream https://.</span></span>
        <span class="switch"><input id="siteVerifyTls" type="checkbox" ${site?.verifyTls === true ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <label class="switch-row span-2">
        <span><span class="switch-label">HTTPS listener</span>
          <span class="hint">Serve this public port over HTTPS using your own certificate.</span></span>
        <span class="switch"><input id="siteTlsEnabled" type="checkbox" ${site?.tls?.enabled === true ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <div class="tls-fields span-2" id="siteTlsFields">
        ${site?.tls?.enabled ? `<div class="note success" style="margin-bottom:12px">${icon('check')}<div>Certificate installed · valid until ${fmtDate(site.tls.validTo)}<br /><span class="mono small">${esc(site.tls.subject || '')}</span></div></div>` : ''}
        <div class="form-grid cols-2">
          <div class="field">
            <label for="siteCertificateFile">Certificate file</label>
            <input id="siteCertificateFile" type="file" accept=".pem,.crt,.cer,application/x-pem-file" />
            <span class="hint">PEM certificate or full chain.</span>
          </div>
          <div class="field">
            <label for="sitePrivateKeyFile">Private key file</label>
            <input id="sitePrivateKeyFile" type="file" accept=".pem,.key,application/x-pem-file" />
            <span class="hint">Unencrypted matching PEM private key.</span>
          </div>
          <div class="field">
            <label for="siteCertificatePem">Or paste certificate PEM</label>
            <textarea id="siteCertificatePem" rows="7" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
          </div>
          <div class="field">
            <label for="sitePrivateKeyPem">Or paste private key PEM</label>
            <textarea id="sitePrivateKeyPem" rows="7" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
          </div>
        </div>
        <div class="note">${icon('info')}<div>When editing, leave both inputs empty to keep the installed certificate. Disabling HTTPS removes its stored certificate. This port will accept HTTPS instead of HTTP.</div></div>
      </div>
      <div class="field span-2">
        <label for="siteNote">${localizedLegacyText('Catatan')}</label>
        <input id="siteNote" type="text" maxlength="300" value="${esc(site?.note || '')}" placeholder="Pemilik aplikasi / tiket" />
      </div>
      <label class="switch-row span-2">
        <span><span class="switch-label">${t('enabledOption')}</span></span>
        <span class="switch"><input id="siteEnabled" type="checkbox" ${site?.enabled !== false ? 'checked' : ''} /><span class="track"></span></span>
      </label>
      <div class="note span-2">${icon('info')}
        <div>Pastikan hostname tidak dipakai situs lain. Setelah disimpan, Nginx divalidasi dengan
        <span class="mono">nginx -t</span>; bila gagal, perubahan dibatalkan otomatis.</div>
      </div>
    </form>`,
    footer: `<button class="btn" data-close>${t('cancel')}</button>
      <button class="btn primary" id="saveSite">${site ? t('saveChanges') : localizedLegacyText('Buat situs')}</button>`,
  });

  const tlsToggle = document.getElementById('siteTlsEnabled');
  const tlsFields = document.getElementById('siteTlsFields');
  const updateTlsFields = () => { tlsFields.hidden = !tlsToggle.checked; };
  tlsToggle.addEventListener('change', updateTlsFields);
  updateTlsFields();
  for (const [fileId, textId] of [['siteCertificateFile', 'siteCertificatePem'], ['sitePrivateKeyFile', 'sitePrivateKeyPem']]) {
    document.getElementById(fileId).addEventListener('change', async (event) => {
      const file = event.currentTarget.files?.[0];
      if (file) document.getElementById(textId).value = await file.text();
    });
  }

  document.getElementById('saveSite').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const body = {
      name: document.getElementById('siteName').value.trim(),
      hosts: document.getElementById('siteHosts').value,
      upstream: document.getElementById('siteUpstream').value.trim(),
      listenPort: Number.parseInt(document.getElementById('siteListenPort').value, 10),
      preserveHost: document.getElementById('sitePreserveHost').checked,
      websocket: document.getElementById('siteWebsocket').checked,
      wafEnabled: document.getElementById('siteWaf').checked,
      verifyTls: document.getElementById('siteVerifyTls').checked,
      tlsEnabled: document.getElementById('siteTlsEnabled').checked,
      certificatePem: document.getElementById('siteCertificatePem').value,
      privateKeyPem: document.getElementById('sitePrivateKeyPem').value,
      enabled: document.getElementById('siteEnabled').checked,
      note: document.getElementById('siteNote').value.trim(),
    };
    if (!body.hosts.trim()) {
      toast(t('requiredHostname'), 'error');
      return;
    }
    if (!body.upstream) {
      toast(t('requiredUpstream'), 'error');
      return;
    }
    setBusy(button, true);
    try {
      if (site) await api(`/api/proxy/sites/${site.id}`, { method: 'PUT', body });
      else await api('/api/proxy/sites', { method: 'POST', body });
      closeModal();
      toast(t(site ? 'siteUpdated' : 'siteCreated'), 'ok');
      refreshChrome();
      await renderProxy();
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  });
}

/* =========================================================================
   Test console
   ========================================================================= */

const TEST_PRESETS = [
  {
    label: 'SQL Injection',
    method: 'GET',
    path: '/?id=1%20UNION%20SELECT%20password%20FROM%20users',
    headers: 'User-Agent: sqlmap/1.7',
    body: '',
  },
  {
    label: 'XSS',
    method: 'GET',
    path: '/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E',
    headers: '',
    body: '',
  },
  {
    label: 'Path traversal',
    method: 'GET',
    path: '/../../../../etc/passwd',
    headers: '',
    body: '',
  },
  {
    label: 'Scanner',
    method: 'GET',
    path: '/?doc=../../etc/passwd&cmd=cat%20/etc/shadow',
    headers: 'User-Agent: sqlmap/1.7',
    body: '',
  },
  {
    label: 'JSON body',
    method: 'POST',
    path: '/api/login',
    headers: 'Content-Type: application/json',
    body: '{"username":"admin","password":"\' OR 1=1 -- "}',
  },
  {
    label: 'Request normal',
    method: 'GET',
    path: '/',
    headers: '',
    body: '',
  },
];

async function renderTest() {
  const view = document.getElementById('view');
  view.innerHTML = `
    ${pageHead(
      'Test Console',
      t('testSub')
    )}
    <div class="test-layout">
      <div class="card">
        <div class="card-head"><div><h3>Request</h3><div class="sub">Dikirim dari manager ke WAF</div></div></div>
        <div class="card-body">
          <div class="preset-list" style="margin-bottom:16px">
            ${TEST_PRESETS.map((preset, index) => `<button type="button" class="preset" data-preset="${index}">${esc(preset.label === 'Request normal' ? t('normalRequest') : preset.label)}</button>`).join('')}
          </div>
          <form id="testForm" class="form-grid">
            <div class="form-grid cols-2">
              <div class="field">
                <label for="testMethod">Method</label>
                <select id="testMethod">
                  ${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
                    .map((method) => `<option value="${method}">${method}</option>`)
                    .join('')}
                </select>
              </div>
              <div class="field">
                <label for="testPath">Path / URL</label>
                <input id="testPath" type="text" value="/" placeholder="/?id=1%27%20OR%201%3D1" />
              </div>
            </div>
            <div class="field">
              <label for="testHost">Hostname virtual host</label>
              <input id="testHost" type="text" placeholder="app.example.com (kosong = upstream default)" />
              <span class="hint">Isi untuk menguji routing dan proteksi WAF situs tertentu.</span>
            </div>
            <div class="field">
              <label for="testHeaders">${t('additionalHeaders')}</label>
              <textarea id="testHeaders" rows="3" placeholder="Content-Type: application/json&#10;X-Custom: value"></textarea>
              <span class="hint">Satu header per baris dengan format <span class="mono">Nama: nilai</span>.</span>
            </div>
            <div class="field">
              <label for="testBody">Body</label>
              <textarea id="testBody" rows="5" placeholder="Body request (untuk POST/PUT/PATCH)"></textarea>
            </div>
            <div class="row">
              <button class="btn primary" type="submit" id="testSubmit">${icon('send', 'sm')} ${t('sendRequest')}</button>
              <span class="muted small">Request akan tercatat di audit log bila memicu rule.</span>
            </div>
          </form>
        </div>
      </div>
      <div id="testResult">
        <div class="card">
          <div class="card-head"><div><h3>Hasil</h3><div class="sub">Response dari WAF dan hasil audit</div></div></div>
          <div class="card-body">${emptyState('terminal', t('noTestFound'), t('noTestSub'))}</div>
        </div>
      </div>
    </div>`;

  const form = document.getElementById('testForm');
  form.querySelectorAll('[data-preset]').forEach((button) => {
    button.addEventListener('click', () => {
      const preset = TEST_PRESETS[Number(button.dataset.preset)];
      document.getElementById('testMethod').value = preset.method;
      document.getElementById('testPath').value = preset.path;
      document.getElementById('testHeaders').value = preset.headers;
      document.getElementById('testBody').value = preset.body;
    });
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = document.getElementById('testSubmit');
    const path = document.getElementById('testPath').value.trim() || '/';
    const headers = {};
    for (const line of document.getElementById('testHeaders').value.split('\n')) {
      const separator = line.indexOf(':');
      if (separator <= 0) continue;
      const name = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (name) headers[name] = value;
    }
    setBusy(button, true, 'Mengirim…');
    document.getElementById('testResult').innerHTML = `<div class="card"><div class="card-body">${loadingBlock()}</div></div>`;
    try {
      const result = await api('/api/test', {
        method: 'POST',
        body: {
          method: document.getElementById('testMethod').value,
          path,
          host: document.getElementById('testHost').value.trim(),
          headers,
          body: document.getElementById('testBody').value,
        },
      });
      renderTestResult(result);
      refreshChrome();
    } catch (err) {
      document.getElementById('testResult').innerHTML = `<div class="card"><div class="card-body">
        <div class="note danger">${icon('alert')}<div><strong>Request gagal.</strong><br />${esc(err.message)}</div></div>
      </div></div>`;
      localizeRendered(document.getElementById('testResult'));
      showApiError(err);
    } finally {
      setBusy(button, false);
    }
  });
}

function renderTestResult(result) {
  const audit = result.audit || {};
  const response = result.response;
  const blocked = Boolean(response && audit.found && (audit.blocked || response.status === 403));
  const statusText = response ? `${response.status} ${response.statusText || ''}`.trim() : localizedLegacyText('Tidak ada response');
  const rules = audit.rules || [];

  let auditHtml = '';
  if (!response) {
    auditHtml = `<div class="note danger">${icon('alert')}<div>${esc(result.error || localizedLegacyText('Tidak ada response dari WAF.'))}</div></div>`;
  } else if (audit.found) {
    auditHtml = `
      <div class="response-head">
        <span class="response-status ${blocked ? 'blocked' : 'ok'}">${response.status}</span>
        <div>
          <div>${blocked ? `<span class="badge blocked">${localizedLegacyText('Diblokir ModSecurity')}</span>` : `<span class="badge detected">${localizedLegacyText('Terdeteksi / lolos')}</span>`}
            ${audit.score ? `<span class="badge warning">Score ${audit.score}</span>` : ''}</div>
          <div class="response-meta">${result.durationMs} ms · marker ${esc(result.marker.slice(0, 8))}</div>
        </div>
        ${audit.uid ? `<button class="btn sm ghost" id="testOpenEvent" style="margin-left:auto">${icon('activity', 'sm')} ${localizedLegacyText('Buka event')}</button>` : ''}
      </div>
      <div class="event-rules">
        ${
          rules.length
            ? rules
                .map(
                  (rule) => `<div class="event-rule"><div class="id">${rule.id}</div>
                    <div><div class="msg">${esc(rule.msg)}</div>
                    <div class="row" style="margin-top:5px">${sevBadge(rule.severity)}
                      ${rule.data ? `<span class="mono small truncate" style="max-width:300px">${esc(rule.data)}</span>` : ''}
                    </div></div></div>`
                )
                .join('')
            : `<div class="muted small">${t('noTriggeredRules')}</div>`
        }
      </div>`;
  } else {
    auditHtml = `
      <div class="response-head">
        <span class="response-status ok">${response.status}</span>
        <div>
          <div><span class="badge allowed">${localizedLegacyText('Tidak ada rule terpicu')}</span></div>
          <div class="response-meta">${result.durationMs} ms · ${esc(statusText)}</div>
        </div>
      </div>
      <div class="note">${icon('info')}
        <div>Request lolos tanpa audit event. Ini normal untuk trafik bersih bila
        <span class="mono">SecAuditEngine RelevantOnly</span>. Ubah ke <span class="mono">On</span> di Settings
        untuk mencatat semua request.</div>
      </div>`;
  }

  const headers = response?.headers || {};
  const bodyText = response?.body || '';

  document.getElementById('testResult').innerHTML = `<div class="card">
    <div class="card-head"><div><h3>Hasil</h3><div class="sub">${esc(result.request?.method || '')} ${esc(result.request?.path || '')}</div></div>
      ${response ? statusBadge(response.status) : ''}</div>
    <div class="card-body">
      ${auditHtml}
      <div class="divider"></div>
      <div class="tabs" id="resultTabs">
        <button class="tab active" data-tab="body">Response body</button>
        <button class="tab" data-tab="headers">Headers (${Object.keys(headers).length})</button>
        <button class="tab" data-tab="request">Request</button>
      </div>
      <div data-pane="body"><pre class="code" style="max-height:340px">${esc(bodyText || '(body kosong)')}</pre></div>
      <div data-pane="headers" hidden>
        <table class="headers-table">${Object.entries(headers)
          .map(([key, value]) => `<tr><td>${esc(key)}</td><td>${esc(value)}</td></tr>`)
          .join('')}</table>
      </div>
      <div data-pane="request" hidden>
        <dl class="kv">
          <dt>Method</dt><dd class="mono">${esc(result.request?.method)}</dd>
          <dt>Path</dt><dd class="mono">${esc(result.request?.path)}</dd>
          <dt>Marker</dt><dd class="mono">${esc(result.marker)}</dd>
        </dl>
        <div class="code-head"><span class="file-name">Header yang dikirim</span></div>
        <pre class="code">${esc(JSON.stringify(result.request?.headers || {}, null, 2))}</pre>
      </div>
    </div>
  </div>`;
  localizeRendered(document.getElementById('testResult'));

  document.querySelectorAll('#resultTabs [data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('#resultTabs [data-tab]').forEach((el) => el.classList.toggle('active', el === button));
      document.querySelectorAll('[data-pane]').forEach((pane) => {
        pane.hidden = pane.dataset.pane !== button.dataset.tab;
      });
    });
  });
  const openEvent = document.getElementById('testOpenEvent');
  if (openEvent) openEvent.addEventListener('click', () => openEventDrawer(audit.uid));
}

/* =========================================================================
   Settings
   ========================================================================= */

async function renderSettings() {
  const view = document.getElementById('view');
  view.innerHTML = loadingBlock();
  const [data, security] = await Promise.all([
    api('/api/settings'),
    api('/api/security-controls'),
  ]);
  const s = data.settings;
  const rl = security.rateLimit;
  const ti = security.threatIntel;
  const ar = security.auditRetention || { enabled: true, days: 30 };
  const ep = security.errorPages || { enabled: true, language: preferences.language || 'en', brand: 'AsekWAF', accent: '#2dd4bf', supportText: '', pages: {} };
  const cu = security.crsUpdate || {};
  const cf = security.cveRuleFeeds || { enabled: false, autoSync: true, sources: [], rules: [] };
  state.settings = s;

  view.innerHTML = `
    ${pageHead(
      'Settings',
      t('settingsSub'),
      `<button class="btn sm" id="viewFiles">${icon('file', 'sm')} ${t('viewFiles')}</button>
       <button class="btn sm" id="viewLogs">${icon('terminal', 'sm')} Log container</button>`
    )}
    <form id="settingsForm" class="settings-layout">
      <section class="card settings-section">
        <h3>${t('language')}</h3>
        <p>Bahasa antarmuka dan preset halaman error dikelola terpusat dari pengaturan ini.</p>
        <div class="form-grid cols-2">
          <div class="field">
            <label for="uiLanguage">${t('language')}</label>
            <select id="uiLanguage">
              <option value="en" ${preferences.language === 'en' ? 'selected' : ''}>English (default)</option>
              <option value="id" ${preferences.language === 'id' ? 'selected' : ''}>Indonesia</option>
              <option value="zh" ${preferences.language === 'zh' ? 'selected' : ''}>中文</option>
              <option value="ar" ${preferences.language === 'ar' ? 'selected' : ''}>العربية</option>
              <option value="ja" ${preferences.language === 'ja' ? 'selected' : ''}>日本語</option>
            </select>
            <span class="hint">Berlaku untuk navigasi, halaman admin, format tanggal, dan halaman error. Arabic otomatis menggunakan RTL.</span>
          </div>
        </div>
        <div class="row mt-16"><button class="btn primary" type="button" id="saveUiLanguage">${icon('save', 'sm')} ${t('save')}</button></div>
      </section>

      <section class="card settings-section">
        <h3>ModSecurity engine</h3>
        <p>Mode blocking menentukan apakah request yang melewati threshold diblokir atau hanya dicatat.</p>
        <div class="segmented" id="engineSegment" role="group" aria-label="Engine mode">
          ${['On', 'DetectionOnly', 'Off']
            .map((mode) => `<button type="button" data-engine="${mode}" class="${s.engineMode === mode ? 'active' : ''}">${mode}</button>`)
            .join('')}
        </div>
        <div class="form-grid cols-2 mt-16">
          <div class="field">
            <label for="setAuditEngine">Audit engine</label>
            <select id="setAuditEngine">
              ${['RelevantOnly', 'On', 'Off']
                .map((mode) => `<option value="${mode}" ${s.auditEngine === mode ? 'selected' : ''}>${mode}</option>`)
                .join('')}
            </select>
            <span class="hint">RelevantOnly mencatat request yang memicu rule (disarankan).</span>
          </div>
          <div class="field">
            <label for="setReportingLevel">Reporting level</label>
            <select id="setReportingLevel">
              ${[0, 1, 2, 3, 4, 5].map((level) => `<option value="${level}" ${Number(s.reportingLevel) === level ? 'selected' : ''}>${level}</option>`).join('')}
            </select>
          </div>
          <div class="field">
            <label for="setReqBody">Request body limit (byte)</label>
            <input id="setReqBody" type="number" min="1024" step="1024" value="${s.requestBodyLimit}" />
            <span class="hint">Saat ini ${fmtBytes(s.requestBodyLimit)}.</span>
          </div>
          <div class="field">
            <label for="setRespBody">Response body limit (byte)</label>
            <input id="setRespBody" type="number" min="0" step="1024" value="${s.responseBodyLimit}" />
            <span class="hint">Saat ini ${fmtBytes(s.responseBodyLimit)}. 0 = tanpa batas.</span>
          </div>
        </div>
      </section>

      <section class="card settings-section">
        <h3>Paranoia & anomaly threshold</h3>
        <p>${t('paranoiaDesc')}</p>
        <label class="form-label">Blocking paranoia level</label>
        <div class="paranoia-grid mt-8" id="paranoiaGrid">
          ${[1, 2, 3, 4]
            .map(
              (pl) => `<div class="paranoia-option ${Number(s.paranoia) === pl ? 'active' : ''}" data-pl="${pl}">
                <strong>PL ${pl}</strong>
                <span>${pl === 1 ? t('plBasic') : pl === 2 ? t('plBalanced') : pl === 3 ? t('plStrict') : t('plVeryStrict')}</span>
              </div>`
            )
            .join('')}
        </div>
        <div class="form-grid cols-2 mt-16">
          <div class="field">
            <label for="setDetectionParanoia">Detection paranoia level</label>
            <select id="setDetectionParanoia">
              ${[1, 2, 3, 4].map((pl) => `<option value="${pl}" ${Number(s.detectionParanoia) === pl ? 'selected' : ''}>PL ${pl}</option>`).join('')}
            </select>
            <span class="hint">Tidak boleh lebih rendah dari blocking PL.</span>
          </div>
          <div class="field">
            <label for="setInbound">Inbound anomaly threshold</label>
            <input id="setInbound" type="number" min="1" max="10000" value="${s.inboundThreshold}" />
          </div>
          <div class="field">
            <label for="setOutbound">Outbound anomaly threshold</label>
            <input id="setOutbound" type="number" min="1" max="10000" value="${s.outboundThreshold}" />
          </div>
          <div class="field">
            <label for="setMaxArgs">Max arguments</label>
            <input id="setMaxArgs" type="number" min="1" max="100000" value="${s.maxNumArgs}" />
          </div>
        </div>
      </section>

      <section class="card settings-section">
        <h3>Metode & konten yang diizinkan</h3>
        <p>Batasi method HTTP dan content type yang diterima aplikasi Anda.</p>
        <div class="form-grid cols-2">
          <div class="field">
            <label for="setMethods">Allowed methods</label>
            <input id="setMethods" type="text" value="${esc(s.allowedMethods)}" />
            <span class="hint">Pisahkan dengan spasi.</span>
          </div>
          <div class="field">
            <label for="setContentTypes">Allowed request content types</label>
            <input id="setContentTypes" type="text" value="${esc(s.allowedContentTypes)}" />
          </div>
          <div class="field span-2">
            <label for="setExtensions">Restricted file extensions</label>
            <textarea id="setExtensions" rows="4">${esc(s.restrictedExtensions)}</textarea>
            <span class="hint">Format CRS: setiap ekstensi diapit spasi dan diakhiri <span class="mono">/</span>.</span>
          </div>
        </div>
      </section>

      <section class="card settings-section">
        <h3>Rate limiter</h3>
        <p>Batasi jumlah request per alamat IP di seluruh upstream. Request yang melampaui batas mendapat HTTP 429.</p>
        <div class="form-grid cols-2">
          <div class="field">
            <label for="rateEnabled">Status</label>
            <select id="rateEnabled">
              <option value="false" ${!rl.enabled ? 'selected' : ''}>${t('disabledOption')}</option>
              <option value="true" ${rl.enabled ? 'selected' : ''}>${t('enabledOption')}</option>
            </select>
          </div>
          <div class="field">
            <label for="rateRpm">Request per menit / IP</label>
            <input id="rateRpm" type="number" min="1" max="100000" value="${rl.requestsPerMinute}" />
          </div>
          <div class="field">
            <label for="rateBurst">Burst</label>
            <input id="rateBurst" type="number" min="0" max="100000" value="${rl.burst}" />
            <span class="hint">Kelonggaran request sesaat sebelum ditolak.</span>
          </div>
          <div class="field">
            <label for="rateNodelay">Perilaku burst</label>
            <select id="rateNodelay">
              <option value="true" ${rl.nodelay ? 'selected' : ''}>Nodelay — teruskan langsung</option>
              <option value="false" ${!rl.nodelay ? 'selected' : ''}>Delay — antrekan bertahap</option>
            </select>
          </div>
        </div>
        <div class="row mt-16"><button class="btn primary" type="button" id="saveRateLimit">${icon('save', 'sm')} ${t('saveRateLimit')}</button></div>
      </section>

      <section class="card settings-section">
        <h3>Community threat intelligence</h3>
        <p>${t('threatDesc')}</p>
        <div class="form-grid cols-2">
          <div class="field">
            <label for="threatEnabled">${t('protectionStatus')}</label>
            <select id="threatEnabled">
              <option value="false" ${!ti.enabled ? 'selected' : ''}>${t('disabledOption')}</option>
              <option value="true" ${ti.enabled ? 'selected' : ''}>${t('enabledOption')}</option>
            </select>
          </div>
          <div class="field">
            <label for="threatRefresh">Interval sinkronisasi (jam)</label>
            <input id="threatRefresh" type="number" min="1" max="720" value="${ti.refreshHours}" />
          </div>
          <div class="field span-2">
            <label>${t('blocklistSources')}</label>
            <div class="source-grid">
              ${security.threatSources.map((source) => `<label class="source-option">
                <input type="checkbox" name="threatSource" value="${esc(source.id)}" ${ti.sources.includes(source.id) ? 'checked' : ''} />
                <span><strong>${esc(source.name)}</strong><small>${esc(source.description)}</small></span>
              </label>`).join('')}
            </div>
          </div>
        </div>
        <div class="status-panel mt-16">
          <div class="status-item"><span class="label">Entri aktif</span><span class="value">${fmtNum(ti.count)}</span></div>
          <div class="status-item"><span class="label">Sinkronisasi terakhir</span><span class="value">${ti.lastSync ? fmtDate(ti.lastSync) : 'belum pernah'}</span></div>
          ${ti.lastError ? `<div class="status-item"><span class="label">Peringatan</span><span class="value">${esc(ti.lastError)}</span></div>` : ''}
        </div>
        <div class="row mt-16">
          <button class="btn primary" type="button" id="saveThreatIntel">${icon('save', 'sm')} ${t('saveThreatIntel')}</button>
          <button class="btn" type="button" id="syncThreatIntel">${icon('download', 'sm')} ${t('syncNow')}</button>
        </div>
      </section>

      <section class="card settings-section">
        <h3>${t('auditRetentionTitle')}</h3>
        <p>${t('auditRetentionDesc')}</p>
        <div class="form-grid cols-2">
          <div class="field">
            <label for="auditRetentionEnabled">${t('autoPrune')}</label>
            <select id="auditRetentionEnabled">
              <option value="true" ${ar.enabled ? 'selected' : ''}>${t('enabledOption')}</option>
              <option value="false" ${!ar.enabled ? 'selected' : ''}>${t('disabledOption')}</option>
            </select>
          </div>
          <div class="field">
            <label for="auditRetentionDays">${t('keepLogsDays')}</label>
            <input id="auditRetentionDays" type="number" min="1" max="3650" value="${ar.days || 30}" />
            <span class="hint">${t('retentionRange')}</span>
          </div>
        </div>
        <div class="status-panel mt-16">
          <div class="status-item"><span class="label">${t('lastPrune')}</span><span class="value">${ar.lastPrune ? fmtDate(ar.lastPrune) : t('never')}</span></div>
          <div class="status-item"><span class="label">${t('lastResult')}</span><span class="value">${fmtNum(ar.lastRemoved || 0)} ${t('removed')} · ${fmtNum(ar.lastKept || 0)} ${t('kept')}</span></div>
          <div class="status-item"><span class="label">${t('lastSize')}</span><span class="value">${fmtBytes(ar.lastSizeBefore || 0)} → ${fmtBytes(ar.lastSizeAfter || 0)}</span></div>
          ${ar.lastError ? `<div class="status-item"><span class="label">${t('errorLabel')}</span><span class="value danger-text">${esc(ar.lastError)}</span></div>` : ''}
        </div>
        <div class="row mt-16">
          <button class="btn primary" type="button" id="saveAuditRetention">${icon('save', 'sm')} ${t('saveRetention')}</button>
          <button class="btn" type="button" id="pruneAuditNow">${icon('trash', 'sm')} ${t('pruneNow')}</button>
        </div>
      </section>

      <section class="card settings-section">
        <h3>${t('crsUpdateTitle')}</h3>
        <p>Periksa release resmi CRS di GitHub. Tuning, custom rule, exclusion, dan IP list dipertahankan saat update.</p>
        <div class="status-panel">
          <div class="status-item"><span class="label">${t('installedVersion')}</span><span class="value" id="crsCurrentVersion">${esc(s.crsVersion)}</span></div>
          <div class="status-item"><span class="label">${t('latestVersion')}</span><span class="value" id="crsLatestVersion">${esc(cu.latestVersion || t('checking'))}</span></div>
          <div class="status-item"><span class="label">Status</span><span class="value" id="crsUpdateStatus">${cu.latestVersion ? (cu.available ? t('updateAvailable') : t('upToDate')) : '—'}</span></div>
          <div class="status-item"><span class="label">${t('lastChecked')}</span><span class="value" id="crsCheckedAt">${cu.checkedAt ? fmtDate(cu.checkedAt) : '—'}</span></div>
        </div>
        <div class="row mt-16">
          <button class="btn" type="button" id="checkCrsUpdate">${icon('refresh', 'sm')} ${t('checkUpdate')}</button>
          <button class="btn primary" type="button" id="installCrsUpdate" ${cu.available ? '' : 'disabled'}>${icon('download', 'sm')} ${t('updateCrs')}</button>
        </div>
        <div class="note warn mt-16">${icon('alert')}<div>Update memerlukan akses internet dari container manager dan dapat memutus trafik beberapa detik saat reload.</div></div>
      </section>

      <section class="card settings-section">
        <h3>Managed CVE rule feeds</h3>
        <p>Fetch validated AsekWAF JSON rule feeds after CRS checks. Feed rules use the reserved ID range 9900000–9999999.</p>
        <div class="form-grid cols-2">
          <div class="field"><label for="cveFeedEnabled">Status</label><select id="cveFeedEnabled"><option value="false" ${!cf.enabled ? 'selected' : ''}>${t('disabledOption')}</option><option value="true" ${cf.enabled ? 'selected' : ''}>${t('enabledOption')}</option></select></div>
          <div class="field"><label for="cveFeedAuto">Automatic sync with CRS check</label><select id="cveFeedAuto"><option value="true" ${cf.autoSync ? 'selected' : ''}>${t('enabledOption')}</option><option value="false" ${!cf.autoSync ? 'selected' : ''}>${t('disabledOption')}</option></select></div>
          <div class="field span-2"><label for="cveFeedSources">HTTPS feed URLs (one per line)</label><textarea id="cveFeedSources" rows="4" placeholder="https://security.example.org/asekwaf-cve-rules.json">${esc((cf.sources || []).join('\n'))}</textarea></div>
        </div>
        <div class="status-panel mt-16"><div class="status-item"><span class="label">Managed rules</span><span class="value">${fmtNum(cf.rules?.length || 0)}</span></div><div class="status-item"><span class="label">Last sync</span><span class="value">${cf.lastSync ? fmtDate(cf.lastSync) : t('never')}</span></div>${cf.lastError ? `<div class="status-item"><span class="label">Error</span><span class="value danger-text">${esc(cf.lastError)}</span></div>` : ''}</div>
        <div class="row mt-16"><button class="btn primary" type="button" id="saveCveFeeds">${icon('save','sm')} ${t('save')}</button><button class="btn" type="button" id="syncCveFeeds">${icon('download','sm')} ${t('syncNow')}</button></div>
      </section>

      <section class="card settings-section">
        <h3>Configuration backup</h3>
        <p>Export or import reverse-proxy sites and safe settings. Secrets, certificates, sessions, and audit logs are excluded.</p>
        <input id="configImportFile" type="file" accept="application/json,.json" hidden />
        <div class="row"><button class="btn" type="button" id="exportConfig">${icon('download','sm')} Export configuration</button><button class="btn" type="button" id="importConfig">${icon('upload','sm')} Import configuration</button></div>
      </section>

      <section class="card settings-section">
        <h3>${t('errorPagesTitle')}</h3>
        <p>${t('errorPagesDesc')}</p>
        <div class="form-grid cols-2">
          <div class="field">
            <label for="errorPagesEnabled">${t('statusLabel')}</label>
            <select id="errorPagesEnabled"><option value="true" ${ep.enabled ? 'selected' : ''}>${t('enabledOption')}</option><option value="false" ${!ep.enabled ? 'selected' : ''}>${t('disabledOption')}</option></select>
          </div>
          <div class="field">
            <label for="errorPageLanguage">${t('errorPageLanguage')}</label>
            <select id="errorPageLanguage">
              <option value="en" ${(ep.language || 'en') === 'en' ? 'selected' : ''}>English (default)</option>
              <option value="id" ${ep.language === 'id' ? 'selected' : ''}>Indonesia</option>
              <option value="zh" ${ep.language === 'zh' ? 'selected' : ''}>中文</option>
              <option value="ar" ${ep.language === 'ar' ? 'selected' : ''}>العربية</option>
              <option value="ja" ${ep.language === 'ja' ? 'selected' : ''}>日本語</option>
            </select>
            <span class="hint">${t('errorLanguageHint')}</span>
          </div>
          <div class="field">
            <label for="errorAccent">${t('accentColor')}</label>
            <input id="errorAccent" type="color" value="${esc(ep.accent || '#2dd4bf')}" />
          </div>
          <div class="field">
            <label for="errorBrand">${t('brandName')}</label>
            <input id="errorBrand" maxlength="80" value="${esc(ep.brand || 'AsekWAF')}" />
          </div>
          <div class="field">
            <label for="errorSupport">${t('supportText')}</label>
            <input id="errorSupport" maxlength="300" value="${esc(ep.supportText || '')}" />
          </div>
          ${[400, 403, 404, 429, 500, 502, 503, 504].map((code) => `<div class="field">
            <label for="errorTitle${code}">${code} · ${t('titleLabel')}</label>
            <input id="errorTitle${code}" maxlength="100" value="${esc(ep.pages?.[code]?.title || '')}" />
            <textarea id="errorMessage${code}" rows="2" maxlength="500" aria-label="${t('messageLabel')} ${code}">${esc(ep.pages?.[code]?.message || '')}</textarea>
          </div>`).join('')}
        </div>
        <div class="row mt-16"><button class="btn primary" type="button" id="saveErrorPages">${icon('save', 'sm')} ${t('saveErrorPages')}</button></div>
      </section>

      <section class="card settings-section">
        <h3>Status sistem</h3>
        <p>Informasi container dan lokasi file yang dikelola panel.</p>
        <div class="form-grid cols-2">
          <div>
            <div class="status-panel">
              <div class="status-item"><span class="label">Docker</span><span class="value">${data.dockerAvailable ? 'tersedia' : 'tidak tersedia'}</span></div>
              <div class="status-item"><span class="label">Container</span><span class="value mono">${esc(data.container?.name || '—')}</span></div>
              <div class="status-item"><span class="label">Status</span><span class="value">${esc(data.container?.status || '—')}</span></div>
              <div class="status-item"><span class="label">Image</span><span class="value mono truncate" style="max-width:280px">${esc(data.container?.image || '—')}</span></div>
              <div class="status-item"><span class="label">CRS version</span><span class="value">${esc(s.crsVersion)}</span></div>
              <div class="status-item"><span class="label">Health</span><span class="value">${esc(data.container?.health || '—')}</span></div>
            </div>
          </div>
          <div>
            <dl class="kv">
              <dt>Config</dt><dd class="mono small">${esc(data.paths.config)}</dd>
              <dt>CRS</dt><dd class="mono small">${esc(data.paths.crs)}</dd>
              <dt>Nginx / proxy</dt><dd class="mono small">${esc(data.paths.nginx || '—')}</dd>
              <dt>Audit log</dt><dd class="mono small">${esc(data.paths.auditLog)}</dd>
            </dl>
            <div class="row mt-16">
              <button class="btn sm" id="reloadWaf">${icon('refresh', 'sm')} ${t('reloadWaf')}</button>
              <button class="btn sm danger" id="restartWaf">${icon('power', 'sm')} ${t('restartContainer')}</button>
            </div>
            ${data.dockerError ? `<div class="note warn mt-16">${icon('alert')}<div>${esc(data.dockerError)}</div></div>` : ''}
          </div>
        </div>
      </section>

      <div class="settings-actions">
        <span class="muted small" id="settingsDirty">${localizedLegacyText('Tidak ada perubahan')}</span>
        <span class="spacer"></span>
        <button class="btn" type="button" id="settingsReset" disabled>Reset</button>
        <button class="btn primary" type="submit" id="settingsSave" disabled>${icon('save', 'sm')} ${t('saveAndReload')}</button>
      </div>
    </form>`;

  let engineMode = s.engineMode;
  let paranoia = Number(s.paranoia);

  const collect = () => ({
    engineMode,
    auditEngine: document.getElementById('setAuditEngine').value,
    reportingLevel: Number(document.getElementById('setReportingLevel').value),
    requestBodyLimit: Number(document.getElementById('setReqBody').value),
    responseBodyLimit: Number(document.getElementById('setRespBody').value),
    paranoia,
    detectionParanoia: Number(document.getElementById('setDetectionParanoia').value),
    inboundThreshold: Number(document.getElementById('setInbound').value),
    outboundThreshold: Number(document.getElementById('setOutbound').value),
    maxNumArgs: Number(document.getElementById('setMaxArgs').value),
    allowedMethods: document.getElementById('setMethods').value,
    allowedContentTypes: document.getElementById('setContentTypes').value,
    restrictedExtensions: document.getElementById('setExtensions').value,
  });

  const baseline = JSON.stringify(collect());
  const saveButton = document.getElementById('settingsSave');
  const resetButton = document.getElementById('settingsReset');
  const dirtyLabel = document.getElementById('settingsDirty');

  const updateDirty = () => {
    const dirty = JSON.stringify(collect()) !== baseline;
    saveButton.disabled = !dirty;
    resetButton.disabled = !dirty;
    dirtyLabel.textContent = localizedLegacyText(dirty ? 'Ada perubahan belum disimpan' : 'Tidak ada perubahan');
    dirtyLabel.style.color = dirty ? 'var(--warning)' : '';
  };

  document.querySelectorAll('#engineSegment [data-engine]').forEach((button) => {
    button.addEventListener('click', () => {
      engineMode = button.dataset.engine;
      document.querySelectorAll('#engineSegment [data-engine]').forEach((el) => el.classList.toggle('active', el === button));
      updateDirty();
    });
  });

  document.querySelectorAll('#paranoiaGrid [data-pl]').forEach((option) => {
    option.addEventListener('click', () => {
      paranoia = Number(option.dataset.pl);
      document.querySelectorAll('#paranoiaGrid [data-pl]').forEach((el) => el.classList.toggle('active', el === option));
      const detection = document.getElementById('setDetectionParanoia');
      if (Number(detection.value) < paranoia) detection.value = String(paranoia);
      updateDirty();
    });
  });

  const form = document.getElementById('settingsForm');
  form.querySelectorAll('input, select, textarea').forEach((el) => {
    el.addEventListener('input', updateDirty);
    el.addEventListener('change', updateDirty);
  });

  resetButton.addEventListener('click', () => renderSettings());

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = collect();
    if (payload.engineMode === 'Off') {
      const ok = await confirmDialog({
        title: 'Matikan ModSecurity?',
        message: 'Engine Off membuat WAF hanya menjadi reverse proxy tanpa proteksi. Lanjutkan hanya untuk maintenance.',
        confirmLabel: 'Matikan engine',
      });
      if (!ok) return;
    }
    if (payload.detectionParanoia < payload.paranoia) {
      toast('Detection paranoia tidak boleh lebih rendah dari blocking paranoia.', 'error');
      return;
    }
    setBusy(saveButton, true, 'Menyimpan & reload…');
    try {
      const result = await api('/api/settings', { method: 'PUT', body: payload });
      state.files = null;
      toast(t(result.reload?.skipped ? 'settingsReloadSkipped' : 'settingsReloaded'), 'ok');
      refreshChrome();
      await renderSettings();
    } catch (err) {
      setBusy(saveButton, false);
      updateDirty();
      showApiError(err);
    }
  });

  document.getElementById('viewFiles').addEventListener('click', () => openFilesDrawer('override'));
  document.getElementById('viewLogs').addEventListener('click', async () => {
    try {
      const system = await api('/api/system');
      openDrawer({
        title: 'Log container WAF',
        subtitle: `120 baris terakhir · ${esc(WAF_LABEL)}`,
        body: `<div class="code-head"><span class="file-name">docker logs</span>
            <button class="btn sm ghost" id="copyLogs" style="margin-left:auto">${icon('copy', 'sm')} Copy</button></div>
          <pre class="code">${esc(system.logs || 'Log tidak tersedia (Docker socket tidak dapat diakses).')}</pre>`,
      });
      document.getElementById('copyLogs').addEventListener('click', () => copyText(system.logs || ''));
    } catch (err) {
      showApiError(err);
    }
  });
  document.getElementById('reloadWaf').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, 'Reload…');
    try {
      const result = await api('/api/system/reload', { method: 'POST' });
      toast(result.message || 'WAF di-reload.', 'ok');
      refreshChrome();
    } catch (err) {
      showApiError(err);
    } finally {
      setBusy(button, false);
    }
  });
  document.getElementById('restartWaf').addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Restart container WAF?',
      message: 'Container akan di-restart. Trafik akan terputus beberapa detik.',
      confirmLabel: 'Restart',
    });
    if (!ok) return;
    try {
      await api('/api/system/restart', { method: 'POST' });
      toast('Container WAF direstart.', 'ok');
      refreshChrome();
    } catch (err) {
      showApiError(err);
    }
  });

  document.getElementById('saveRateLimit').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true);
    try {
      const result = await api('/api/security-controls/rate-limit', {
        method: 'PUT',
        body: {
          enabled: document.getElementById('rateEnabled').value === 'true',
          requestsPerMinute: Number(document.getElementById('rateRpm').value),
          burst: Number(document.getElementById('rateBurst').value),
          nodelay: document.getElementById('rateNodelay').value === 'true',
        },
      });
      toast(t(result.reload?.skipped ? 'rateReloadSkipped' : 'rateApplied'), 'ok');
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(button, false);
    }
  });

  document.getElementById('saveCveFeeds').addEventListener('click', async (event) => {
    const button = event.currentTarget; setBusy(button, true);
    try { await api('/api/cve-rule-feeds', { method:'PUT', body:{ enabled:document.getElementById('cveFeedEnabled').value === 'true', autoSync:document.getElementById('cveFeedAuto').value === 'true', sources:document.getElementById('cveFeedSources').value } }); toast('CVE rule feed settings saved.', 'ok'); await renderSettings(); }
    catch (err) { setBusy(button, false); showApiError(err); }
  });
  document.getElementById('syncCveFeeds').addEventListener('click', async (event) => {
    const button = event.currentTarget; setBusy(button, true);
    try { const result = await api('/api/cve-rule-feeds/sync', { method:'POST' }); toast(`${result.count || 0} managed CVE rules synchronized.`, 'ok'); await renderSettings(); }
    catch (err) { setBusy(button, false); showApiError(err); }
  });
  document.getElementById('exportConfig').addEventListener('click', async () => {
    try { const data = await api('/api/config/export'); const blob = new Blob([JSON.stringify(data, null, 2)], { type:'application/json' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `asekwaf-config-${new Date().toISOString().slice(0,10)}.json`; link.click(); URL.revokeObjectURL(link.href); toast('Configuration exported.', 'ok'); } catch (err) { showApiError(err); }
  });
  document.getElementById('importConfig').addEventListener('click', () => document.getElementById('configImportFile').click());
  document.getElementById('configImportFile').addEventListener('change', async (event) => {
    const file = event.target.files?.[0]; if (!file) return;
    try { if (file.size > 2 * 1024 * 1024) throw new Error('Configuration file exceeds 2 MB.'); const data = JSON.parse(await file.text()); await api('/api/config/import', { method:'POST', body:data }); toast('Configuration imported and WAF reloaded.', 'ok'); await renderSettings(); }
    catch (err) { showApiError(err); } finally { event.target.value = ''; }
  });

  document.getElementById('saveThreatIntel').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const sources = [...document.querySelectorAll('[name="threatSource"]:checked')].map((el) => el.value);
    setBusy(button, true);
    try {
      await api('/api/security-controls/threat-intel', {
        method: 'PUT',
        body: {
          enabled: document.getElementById('threatEnabled').value === 'true',
          refreshHours: Number(document.getElementById('threatRefresh').value),
          sources,
        },
      });
      toast(t('threatSaved'), 'ok');
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(button, false);
    }
  });

  document.getElementById('syncThreatIntel').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, 'Mengunduh blocklist…');
    try {
      const result = await api('/api/security-controls/threat-intel/sync', { method: 'POST' });
      toast(`${fmtNum(result.threatIntel.count)} entri threat intelligence diterapkan.`, 'ok');
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(button, false);
    }
  });

  document.getElementById('saveAuditRetention').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true);
    try {
      await api('/api/security-controls/audit-retention', {
        method: 'PUT',
        body: {
          enabled: document.getElementById('auditRetentionEnabled').value === 'true',
          days: Number(document.getElementById('auditRetentionDays').value),
        },
      });
      toast(t('retentionSaved'), 'ok');
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(button, false);
    }
  });

  document.getElementById('saveUiLanguage').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const language = document.getElementById('uiLanguage').value;
    setBusy(button, true, t('save'));
    try {
      const synced = await syncErrorPagesLanguage(language);
      if (!synced) throw new Error('Failed to save the language preset to custom error pages.');
      preferences.language = language;
      localStorage.setItem('openwaf.language', language);
      applyPreferences();
      await mountShell();
      applyRoute();
      toast(t('languageSaved'), 'ok');
    } catch (err) {
      setBusy(button, false);
      showApiError(err);
    }
  });

  document.getElementById('pruneAuditNow').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, 'Memangkas log…');
    try {
      const response = await api('/api/security-controls/audit-retention/prune', { method: 'POST' });
      toast(`${fmtNum(response.result.removed)} ${t('removed')} · ${fmtNum(response.result.kept)} ${t('kept')}`, 'ok');
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(button, false);
    }
  });

  document.getElementById('errorPageLanguage').addEventListener('change', (event) => {
    const preset = ERROR_PAGE_PRESETS[event.currentTarget.value] || ERROR_PAGE_PRESETS.en;
    document.getElementById('errorSupport').value = preset.support;
    for (const code of [400, 403, 404, 429, 500, 502, 503, 504]) {
      document.getElementById(`errorTitle${code}`).value = preset.pages[code][0];
      document.getElementById(`errorMessage${code}`).value = preset.pages[code][1];
    }
  });

  document.getElementById('saveErrorPages').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const pages = {};
    for (const code of [400, 403, 404, 429, 500, 502, 503, 504]) {
      pages[code] = {
        title: document.getElementById(`errorTitle${code}`).value.trim(),
        message: document.getElementById(`errorMessage${code}`).value.trim(),
      };
    }
    setBusy(button, true, 'Menyimpan & reload…');
    try {
      await api('/api/security-controls/error-pages', {
        method: 'PUT',
        body: {
          enabled: document.getElementById('errorPagesEnabled').value === 'true',
          language: document.getElementById('errorPageLanguage').value,
          brand: document.getElementById('errorBrand').value.trim(),
          accent: document.getElementById('errorAccent').value,
          supportText: document.getElementById('errorSupport').value.trim(),
          pages,
        },
      });
      toast(t('errorPagesSaved'), 'ok');
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(button, false);
    }
  });

  const installCrsButton = document.getElementById('installCrsUpdate');
  const applyCrsCheckResult = (result) => {
    const latest = document.getElementById('crsLatestVersion');
    const status = document.getElementById('crsUpdateStatus');
    const checked = document.getElementById('crsCheckedAt');
    if (!latest || !status || !checked) return;
    latest.textContent = result.latestVersion || '—';
    status.textContent = result.available ? t('updateAvailable') : t('upToDate');
    checked.textContent = result.checkedAt ? fmtDate(result.checkedAt) : '—';
    installCrsButton.disabled = !result.available;
  };
  document.getElementById('checkCrsUpdate').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, 'Memeriksa…');
    try {
      const result = await api('/api/crs/update?force=1');
      applyCrsCheckResult(result);
      if (result.stale) toast(t('checkFailedCached'), 'error');
      else toast(result.available ? `${t('updateAvailable')}: CRS ${result.latestVersion}.` : t('crsLatestToast'), result.available ? 'info' : 'ok');
    } catch (err) {
      showApiError(err);
    } finally {
      setBusy(button, false);
    }
  });

  installCrsButton.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Update OWASP CRS?',
      message: 'Release terbaru akan diunduh, divalidasi, lalu WAF di-reload. Jika validasi gagal, versi lama dipulihkan.',
      confirmLabel: 'Download & update',
      danger: false,
    });
    if (!ok) return;
    setBusy(installCrsButton, true, 'Mengupdate CRS…');
    try {
      const result = await api('/api/crs/update', { method: 'POST' });
      state.files = null;
      toast(result.updated ? `CRS berhasil diupdate ke ${result.to}.` : result.message, 'ok');
      refreshChrome();
      await renderSettings();
    } catch (err) {
      showApiError(err);
      setBusy(installCrsButton, false);
    }
  });

  const checkedAt = cu.checkedAt ? Date.parse(cu.checkedAt) : 0;
  if (!checkedAt || Date.now() - checkedAt > 6 * 3600_000) {
    api('/api/crs/update')
      .then((result) => {
        applyCrsCheckResult(result);
        if (result.stale) toast(t('checkFailedCached'), 'info');
      })
      .catch((err) => showApiError(err));
  }
}

const WAF_LABEL = 'asekwaf-waf';

async function openFilesDrawer(active = 'setup') {
  let files = state.files;
  if (!files) {
    files = await api('/api/system/files');
    state.files = files;
  }
  const tabs = [
    ['setup', 'crs-setup.conf'],
    ['override', 'modsecurity-override.conf'],
    ['zzz', 'REQUEST-905-OPENWAF-CUSTOM.conf'],
    ['before', 'REQUEST-900-EXCLUSION…'],
    ['defaultUpstream', 'default-upstream.conf'],
    ['sites', 'sites.conf'],
    ['rateLimitZone', 'rate-limit-zone.conf'],
    ['rateLimitLocation', 'rate-limit-location.conf'],
  ];
  let current = active;
  openDrawer({
    title: localizedLegacyText('File konfigurasi'),
    subtitle: 'Dikelola otomatis oleh AsekWAF',
    body: `<div class="file-tabs" id="fileTabs">
        ${tabs
          .map(
            ([key, label]) => `<button type="button" class="btn sm ${key === active ? 'primary' : 'ghost'}" data-file-tab="${key}">${esc(label)}</button>`
          )
          .join('')}
      </div>
      <div class="code-head"><span class="file-name" id="fileName">${esc(tabs.find(([key]) => key === active)?.[1] || '')}</span>
        <button class="btn sm ghost" id="copyFile" style="margin-left:auto">${icon('copy', 'sm')} Copy</button></div>
      <pre class="code" id="fileContent">${esc(files[current] || '(kosong)')}</pre>`,
  });
  const update = (key) => {
    current = key;
    document.querySelectorAll('#fileTabs [data-file-tab]').forEach((button) => {
      button.className = `btn sm ${button.dataset.fileTab === key ? 'primary' : 'ghost'}`;
    });
    document.getElementById('fileName').textContent = tabs.find(([item]) => item === key)?.[1] || '';
    document.getElementById('fileContent').textContent = files[key] || '(kosong)';
  };
  document.querySelectorAll('#fileTabs [data-file-tab]').forEach((button) => {
    button.addEventListener('click', () => update(button.dataset.fileTab));
  });
  document.getElementById('copyFile').addEventListener('click', () => copyText(files[current] || ''));
}

/* =========================================================================
   Bootstrap
   ========================================================================= */

async function init() {
  try {
    state.session = await api('/api/session', { auth: false });
  } catch (err) {
    renderLogin(err.message);
    return;
  }
  if (!state.session.authenticated) {
    renderLogin();
    return;
  }
  if (!window.location.hash) history.replaceState(null, '', '#/dashboard');
  syncErrorPagesLanguage(preferences.language);
  await mountShell();
  applyRoute();
}

window.addEventListener('hashchange', () => applyRoute());
init();
