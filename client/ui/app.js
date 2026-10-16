'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  let nonce = window.location.hash.slice(1);
  history.replaceState(null, '', '/');
  const SCENES = Object.freeze([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
  const STEP_ART_KEYS = new Set([
    'g00-s01', 'g00-s02',
    'g01-s01', 'g01-s02', 'g01-s03', 'g01-s04',
    'g02-s01', 'g02-s02', 'g02-s03',
    'g03-s01', 'g03-s02', 'g03-s03', 'g03-s04', 'g03-s05', 'g03-s06', 'g03-s07', 'g03-s08', 'g03-s09', 'g03-s10',
    'g04-s01', 'g04-s02', 'g04-s03', 'g04-s04', 'g04-s05', 'g04-s06',
    'g05-s01', 'g05-s02', 'g05-s03',
    'g06-s01', 'g06-s02', 'g06-s03', 'g06-s04', 'g06-s05', 'g06-s06', 'g06-s07',
    'g07-s01', 'g07-s02', 'g07-s03',
    'g08-s01', 'g08-s02', 'g08-s03', 'g08-s04',
    'g09-s01', 'g09-s02', 'g09-s03', 'g09-s04', 'g09-s05', 'g09-s06',
    'g10-s01', 'g10-s02', 'g10-s03',
    'g11-s01', 'g11-s02', 'g11-s03', 'g11-s04', 'g11-s05', 'g11-s06',
    'g12-s01', 'g12-s02', 'g12-s03', 'g12-s04', 'g12-s05',
    'g13-s01', 'g13-s02', 'g13-s03'
  ]);
  let activeStep = 0;
  const innerPositions = new Map();
  let state = null;
  let polling = false;
  let pollPromise = null;
  let submittingJob = false;
  let closed = false;
  let toastTimer;
  let lastJobKey = '';
  let handoffVersion = 0;
  let cardVersion = 0;
  let walletVersion = 0;
  let walletTimer;
  let walletChallenge = null;
  let walletDetails = [];
  let walletLockPending = false;
  let phoneRequestPending = false;
  const dailyPositions = new Map();
  let lastWalletJob = '';
  let nextReadyCheck = 0;
  let readinessRequest = false;
  let autoCleanerRequest = false;
  let autoCleanerScheduled = false;
  let nextAutoCleanerCheck = 0;
  const busyIds = ['feather-action', 'feather-stop', 'feather-connect', 'launch-tor', 'check-tor', 'download-tails', 'refresh-disks', 'write-usb', 'install-server', 'resume-install', 'recover-card', 'start-workstation', 'check-ready', 'audit-server', 'prepare-handoff', 'show-card', 'wallet-create', 'wallet-unlock', 'wallet-reveal', 'wallet-confirm-backup', 'wallet-load', 'wallet-receive-list', 'wallet-lock', 'phone-list', 'phone-install', 'phone-close', 'phone-close-guide', 'auto-cleaner-check'];

  function showError(message) {
    $('notice').textContent = message;
    $('notice').hidden = false;
    $('notice').scrollIntoView({block: 'nearest'});
  }
  function clearError() { $('notice').hidden = true; $('notice').textContent = ''; }
  function toast(message) {
    $('toast').textContent = message;
    $('toast').hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3500);
  }
  function showStepStart(page) {
    const frame = page.querySelector('.goal-art-frame');
    const sidebar = document.querySelector('.sidebar');
    const inset = window.matchMedia('(max-width: 900px)').matches ? sidebar.getBoundingClientRect().height + 12 : 0;
    const daily = page.querySelector('#daily-guide');
    if (daily && !daily.hidden && !daily.closest('[data-inner-step]').hidden) frame.setAttribute('aria-describedby', 'daily-guide-position daily-guide-title');
    else frame.removeAttribute('aria-describedby');
    frame.focus({preventScroll: true});
    // Measure the page, since the illustration itself can already be sticky.
    window.scrollTo({top: Math.max(0, window.scrollY + page.getBoundingClientRect().top - inset), behavior: 'instant'});
  }
  function go(step) {
    if (!Number.isInteger(step) || step < 0 || step >= SCENES.length || closed) return;
    const leavingGoal = activeStep !== step;
    activeStep = step;
    document.body.dataset.scene = String(SCENES[step]);
    document.querySelectorAll('[data-page]').forEach((page) => { page.hidden = Number(page.dataset.page) !== step; });
    document.querySelectorAll('[data-step]').forEach((button) => {
      const active = Number(button.dataset.step) === step;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'step'); else button.removeAttribute('aria-current');
    });
    $('step-position').textContent = `Этап ${step} из 13 · ${document.querySelector(`[data-step="${step}"] > span:last-child`).firstChild.textContent}`;
    hideSecrets();
    wipeWalletSecrets(leavingGoal || !$('wallet-seed-panel').hidden);
    $('root-password').value = '';
    $('root-password').type = 'password';
    const rootToggle = document.querySelector('[data-toggle="root-password"]');
    rootToggle.textContent = 'Показать';
    rootToggle.setAttribute('aria-pressed', 'false');
    clearError();
    if (step === 5 && state) updateUsb();
    const page = document.querySelector(`[data-page="${step}"]`);
    updateStepArt(page, innerPositions.get(step) || 0);
    collapseWalletControls();
    showStepStart(page);
    scheduleNavReveal();
    if (step === 13) checkAutoCleanerWhenVisible();
  }
  async function api(path, data) {
    if (!nonce) throw new Error('Код этого запуска потерян. Закройте страницу и откройте приложение через его значок. Обновление страницы не сохраняет секреты.');
    if (state && state.closing && path !== '/api/state' && path !== '/api/quit') throw new Error('Приложение завершает работу. Новые операции не запускаются.');
    const options = {method: data === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'omit', headers: {'X-App-Nonce': nonce}};
    if (data !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(data); }
    let response;
    try { response = await fetch(path, options); }
    catch { throw new Error('Нет связи с локальным мастером. Если приложение закрыто, откройте его снова.'); }
    let result;
    try { result = await response.json(); }
    catch { throw new Error('Мастер вернул неизвестный ответ. Перезапустите приложение.'); }
    if (!response.ok) throw new Error(result.error || 'Действие не удалось.');
    return result;
  }
  const shotViewer = $('guide-shot-viewer');
  let shotViewerTrigger = null;

  function verifiedShot(value) {
    if (!value || typeof value.url !== 'string' || typeof value.alt !== 'string'
        || typeof value.caption !== 'string' || !value.alt.trim() || !value.caption.trim()) return null;
    try {
      const url = new URL(value.url, window.location.origin);
      if (url.origin !== window.location.origin || url.username || url.password || url.search || url.hash
          || !/^\/screens\/real\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.png$/.test(url.pathname)) return null;
      return {url: url.href, alt: value.alt, caption: value.caption};
    } catch { return null; }
  }
  function openShot(shot, trigger) {
    if (closed) return;
    shotViewerTrigger = trigger;
    $('guide-shot-viewer-title').textContent = shot.alt;
    $('guide-shot-viewer-image').src = shot.url;
    $('guide-shot-viewer-image').alt = shot.alt;
    $('guide-shot-viewer-caption').textContent = shot.caption;
    shotViewer.classList.remove('shot-viewer-native');
    $('guide-shot-viewer-size').textContent = 'Исходный размер';
    $('guide-shot-viewer-size').setAttribute('aria-pressed', 'false');
    document.body.classList.add('shot-viewer-open');
    shotViewer.showModal();
    $('guide-shot-viewer-frame').scrollTo(0, 0);
    $('guide-shot-viewer-close').focus({preventScroll: true});
  }
  $('guide-shot-viewer-close').addEventListener('click', () => shotViewer.close());
  $('view-scene').addEventListener('click', (event) => {
    const image = document.querySelector(`[data-page="${activeStep}"] [data-goal-image]`);
    if (!image || !image.complete || !image.naturalWidth) return;
    const url = image.getAttribute('src');
    if (!/^\/assets\/(?:microsteps\/g(?:0[0-9]|1[0-3])-s[0-9]{2}|steps\/[A-Za-z0-9_-]+|agent-cover)\.png$/.test(url)) return;
    openShot({url, alt: image.alt,
      caption: 'Художественная иллюстрация текущего действия. Это не снимок программы. Реальные экраны находятся рядом с инструкциями.'}, event.currentTarget);
  });
  $('guide-shot-viewer-size').addEventListener('click', () => {
    const native = shotViewer.classList.toggle('shot-viewer-native');
    $('guide-shot-viewer-size').textContent = native ? 'Вписать в экран' : 'Исходный размер';
    $('guide-shot-viewer-size').setAttribute('aria-pressed', String(native));
    $('guide-shot-viewer-frame').scrollTo(0, 0);
  });
  shotViewer.addEventListener('close', () => {
    document.body.classList.remove('shot-viewer-open');
    $('guide-shot-viewer-image').removeAttribute('src');
    $('guide-shot-viewer-image').alt = '';
    const trigger = shotViewerTrigger;
    shotViewerTrigger = null;
    if (trigger && trigger.isConnected && !trigger.disabled) trigger.focus({preventScroll: true});
  });
  async function loadGuideShots() {
    document.body.dataset.guideShotsState = 'loading';
    try {
      const result = await api('/api/guide-shots');
      if (closed) { document.body.dataset.guideShotsState = 'unavailable'; return; }
      if (!result || !result.shots || typeof result.shots !== 'object' || Array.isArray(result.shots)) {
        throw new Error('Некорректный список снимков.');
      }
      document.querySelectorAll('[data-guide-shot]').forEach((figure) => {
        const key = figure.dataset.guideShot;
        const shot = verifiedShot(result.shots[key]);
        if (!shot) return;
        const image = document.createElement('img');
        image.alt = shot.alt;
        image.loading = 'lazy';
        image.decoding = 'async';
        const frame = document.createElement('div');
        frame.className = 'guide-shot-frame';
        frame.appendChild(image);
        const caption = document.createElement('figcaption');
        caption.id = 'guide-shot-caption-' + key;
        caption.textContent = shot.caption;
        image.setAttribute('aria-describedby', caption.id);
        const enlarge = document.createElement('button');
        enlarge.type = 'button';
        enlarge.className = 'button small secondary guide-shot-zoom';
        enlarge.dataset.enlargeShot = key;
        enlarge.textContent = 'Увеличить снимок';
        enlarge.setAttribute('aria-label', 'Увеличить: ' + shot.alt);
        enlarge.setAttribute('aria-haspopup', 'dialog');
        enlarge.setAttribute('aria-controls', 'guide-shot-viewer');
        enlarge.disabled = true;
        enlarge.addEventListener('click', () => openShot(shot, enlarge));
        image.addEventListener('load', () => { enlarge.disabled = closed; });
        image.addEventListener('error', () => { figure.hidden = true; });
        figure.replaceChildren(frame, caption, enlarge);
        figure.hidden = false;
        image.src = shot.url;
      });
      document.body.dataset.guideShotsState = 'ready';
    } catch {
      // Screenshots are optional evidence. Keep unavailable figures hidden.
      document.body.dataset.guideShotsState = 'unavailable';
    }
  }
  async function perform(path, data = {}) {
    if (closed || submittingJob || (state && state.closing)
        || (state && state.job && state.job.state === 'running' && path !== '/api/job/cancel')) return false;
    submittingJob = true;
    try {
      if (state) render(state);
      clearError();
      await api(path, data);
      // A request started before the acknowledgement can still contain idle state.
      // Wait for it, then observe the accepted operation with a fresh state read.
      if (polling && pollPromise) await pollPromise;
      await poll();
      return true;
    } catch (error) { if (!closed) showError(error.message); return false; }
    finally {
      submittingJob = false;
      if (state && !closed) render(state);
    }
  }
  async function copy(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const input = document.createElement('textarea');
        input.value = text;
        input.setAttribute('aria-label', 'Копируемый текст');
        input.className = 'clipboard-helper';
        document.body.appendChild(input);
        input.focus(); input.select();
        const result = document.execCommand('copy');
        input.value = ''; input.remove();
        if (!result) throw new Error('copy');
      }
      toast('Скопировано. Вставьте в нужное окно.');
    } catch { showError('Браузер не разрешил копирование. Выделите текст или поле и скопируйте вручную.'); }
  }
  function hideSecrets() {
    handoffVersion += 1;
    cardVersion += 1;
    $('handoff-note').value = '';
    $('handoff-panel').hidden = true;
    $('secret-fields').replaceChildren();
    $('secret-card').hidden = true;
    $('show-card').hidden = false;
  }
  function updateUsb() {
    $('usb-verified').textContent = state.usb_verified ? '✓ Подпись проверена в этом запуске' : 'Образ ещё не проверен';
    if (state.usb_written) $('disk-hint').textContent = '✓ Флешка записана и проверена. Извлеките её безопасно.';
    else if ($('disk-hint').textContent.startsWith('✓')) $('disk-hint').textContent = 'Новая запись ещё не подтверждена. Проверьте выбранную флешку и результат операции.';
  }
  function render(next) {
    if (closed) return;
    state = next;
    if (state.closing) { hideSecrets(); wipeWalletSecrets(false); $('root-password').value = ''; }
    const system = state.system;
    const platform = ({Darwin: 'macOS', darwin: 'macOS', Windows: 'Windows', win32: 'Windows', Linux: 'Linux', linux: 'Linux'})[system.platform] || system.platform || 'Ваш компьютер';
    $('device-name').textContent = `${platform} · ${system.architecture || 'архитектура не определена'}`;
    $('device-message').textContent = system.boot_message || 'Для настройки и входа используйте Tor Browser.';
    const apple = /arm64|aarch64/i.test(system.architecture || '') && /mac|darwin/i.test(system.platform || '');
    $('apple-note').hidden = !apple;
    $('tor-state').textContent = state.tor_verified ? '✓ Tor был подтверждён в этом запуске; при подключении мастер проверит снова' : 'Пока не проверен';
    $('connection-state').textContent = state.server_connected ? '✓ Проверенное соединение открыто в этом запуске' : 'Соединение ещё не установлено';
    const offline = state.offline || {};
    $('bundle-state').textContent = offline.message || 'Проверяю файлы полного комплекта…';
    $('download-tails').textContent = offline.tails_available ? 'Подготовить Tails из комплекта' : 'Скачать проверенный Tails через Tor';
    updateUsb();
    $('ready-state').textContent = state.guest_ready ? '✓ Telegram установлен; Tor в Workstation подтверждён последней проверкой' : 'Готовность пока не подтверждена';
    $('ready-state').classList.toggle('ready', state.guest_ready);
    $('safety-state').textContent = state.safety_checked
      ? (state.safety_ok ? '✓ Проверка сервера завершена: проверенные настройки в порядке' : 'Проверка сервера нашла проблему — прочитайте результат ниже')
      : 'Защитные настройки сервера пока не проверены';
    $('safety-state').classList.toggle('ready', Boolean(state.safety_checked && state.safety_ok));
    $('safety-report').textContent = typeof state.safety_report === 'string' ? state.safety_report : '';
    $('safety-details').hidden = !$('safety-report').textContent;
    const job = state.job;
    const running = Boolean(job && job.state === 'running');
    const busy = running || submittingJob || Boolean(state.closing) || phoneRequestPending || autoCleanerRequest;
    busyIds.forEach((id) => { $(id).disabled = busy; });
    $('launch-tor').disabled = busy || !offline.tor_available;
    $('connect-form').querySelector('button[type=submit]').disabled = busy;
    $('quit').disabled = busy;
    $('cancel-job').disabled = submittingJob || Boolean(state.closing);
    renderWallet(busy);
    renderFeather(busy);
    renderPhone(busy);
    renderAutoCleaner(busy);
    checkReadinessWhenVisible();
    checkAutoCleanerWhenVisible();
    $('operation-panel').hidden = !job;
    if (!job) return;
    const names = {'feather-connect':'ПОДКЛЮЧЕНИЕ FEATHER ЧЕРЕЗ TOR','feather-prepare':'ПОДГОТОВКА FEATHER','feather-launch':'ЗАПУСК FEATHER','feather-stop':'ПРОВЕРКА ЗАВЕРШЕНИЯ FEATHER','usb-download':'ПОДГОТОВКА TAILS','usb-write':'ЗАПИСЬ ФЛЕШКИ','tor-start':'ПОДГОТОВКА TOR BROWSER','tor-check':'ПРОВЕРКА TOR','server-connect':'ПРОВЕРКА СОЕДИНЕНИЯ','server-install':'НАСТРОЙКА СЕРВЕРА','server-resume':'ПРОВЕРКА УСТАНОВКИ','server-credentials':'ПОЛУЧЕНИЕ КАРТОЧКИ','server-start':'ЗАПУСК WORKSTATION','server-status':'ПРОВЕРКА ГОТОВНОСТИ','server-audit':'ПРОВЕРКА ЗАЩИТЫ СЕРВЕРА','wallet-create':'СОЗДАНИЕ КОШЕЛЬКА','wallet-unlock':'ОТКРЫТИЕ ХРАНИЛИЩА','wallet-reveal':'ПОДГОТОВКА ФРАЗЫ','wallet-confirm':'ПРОВЕРКА РЕЗЕРВНОЙ КОПИИ','wallet-lock':'ЗАКРЫТИЕ ХРАНИЛИЩА','phone-list':'ПОИСК ANDROID','phone-install':'УСТАНОВКА TOR BROWSER НА ANDROID','phone-close':'ЗАВЕРШЕНИЕ USB-ПОДКЛЮЧЕНИЯ','server-auto-cleaner':'ПРОВЕРКА АВТООЧИСТКИ'};
    $('job-kind').textContent = names[job.kind] || 'ХОД ЗАДАНИЯ';
    const key = `${job.id}:${job.state}:${job.message}`;
    if (key !== lastJobKey) { $('job-message').textContent = job.message; lastJobKey = key; }
    const percent = typeof job.percent === 'number' && Number.isFinite(job.percent) && job.percent >= 0 && job.percent <= 100 ? job.percent : null;
    if (percent === null) $('job-progress').removeAttribute('value'); else $('job-progress').value = percent;
    $('job-progress').hidden = !running;
    $('job-status').textContent = running
      ? (percent === null ? 'Выполняется · точный процент пока неизвестен' : `Выполняется · ${Math.round(percent)}%`)
      : ({done: 'Завершено', error: 'Не завершено — прочитайте сообщение', cancelled: 'Остановлено'})[job.state] || 'Операция остановлена';
    $('job-events').textContent = (job.events || []).join('\n');
    $('cancel-job').hidden = !job.cancellable || !running;
    $('operation-panel').classList.toggle('operation-error', job.state === 'error');
  }
  function renderFeather(busy) {
    const feather = state && state.feather || {};
    const action = $('feather-action');
    const running = feather.running === true;
    const available = feather.available === true;
    const loading = typeof feather.available !== 'boolean';
    const workspaceOpen = feather.workspace_open === true;
    const prepared = feather.prepared === true;
    const canCheckExit = running || (workspaceOpen && prepared);
    const job = state && state.job;
    const featherJob = Boolean(job && typeof job.kind === 'string' && job.kind.startsWith('feather-'));
    const pending = featherJob && job.state === 'running';
    action.textContent = loading ? 'Проверяю файлы Feather…' : !available ? 'Feather недоступен в комплекте' : running ? 'Feather открыт'
      : pending ? 'Подождите завершения операции…' : !workspaceOpen ? 'Открыть хранилище для Feather'
      : prepared ? 'Открыть Feather без сети' : 'Подготовить проверенный Feather';
    action.disabled = busy || !available || running;
    $('feather-stop').hidden = !canCheckExit;
    $('feather-stop').disabled = busy || !canCheckExit;
    $('feather-connect').hidden = !available || !prepared;
    $('feather-connect').disabled = busy || !available || !prepared || !workspaceOpen || running;
    $('feather-network-help').hidden = !available || !prepared;
    const version = typeof feather.version === 'string' ? feather.version : '';
    const checked = typeof feather.checked_on === 'string' ? feather.checked_on : '';
    $('feather-version').textContent = version
      ? `Feather ${version}${checked ? ` · проверка комплекта: ${checked}` : ''}. Файлы и подпись проверяются перед запуском.`
      : loading ? 'Проверяю версию Feather в комплекте…' : 'Версия Feather в этом комплекте не подтверждена.';
    const message = featherJob && ['running', 'error', 'cancelled'].includes(job.state) && typeof job.message === 'string'
      ? job.message : typeof feather.message === 'string' && feather.message
        ? feather.message : loading ? 'Проверяю файлы Feather…' : !available ? 'Проверенный Feather недоступен в этом комплекте или на этой системе.'
          : !workspaceOpen ? 'Сначала откройте своё зашифрованное хранилище. Пароль вводится на этапе кошелька.'
            : running ? (feather.network_mode === 'tor' ? 'Feather запущен через проверенный Tor. Дождитесь синхронизации в его окне.' : 'Feather открыт автономно. Восстановление кошелька продолжите в его окне.')
              : prepared ? 'Проверка завершена. Можно открыть Feather.' : 'Подготовка проверит Feather из комплекта и сохранит его данные в вашем хранилище.';
    if ($('feather-state').textContent !== message) $('feather-state').textContent = message;
    $('feather-state').classList.toggle('ready', prepared && !pending && !(featherJob && job.state === 'error'));
  }
  async function poll() {
    if (closed || !nonce) return;
    if (polling) return pollPromise;
    polling = true;
    pollPromise = (async () => {
      try {
        const next = await api('/api/state');
        if (!closed) render(next);
      } catch (error) { if (!closed) showError(error.message); }
      finally { polling = false; pollPromise = null; }
    })();
    return pollPromise;
  }
  function renderAutoCleaner(busy) {
    const connected = Boolean(state && state.server_connected);
    const installed = Boolean(state && state.server_installed);
    const closing = Boolean(state && state.closing);
    const status = connected && installed && state.auto_cleaner && typeof state.auto_cleaner === 'object' ? state.auto_cleaner : null;
    const candidate = status && status.report && typeof status.report === 'object' ? status.report : null;
    const updated = candidate && typeof candidate.updated_at === 'string' ? Date.parse(candidate.updated_at) : NaN;
    const age = Date.now() - updated;
    const report = Number.isFinite(age) && age >= -30000 && age <= 45000 ? candidate : null;
    const warnings = [];
    if (report && report.watch_error) warnings.push('Наблюдение за папкой сообщает об ошибке. Повторите проверку.');
    if (report && report.scan_limited) warnings.push('Достигнут предел проверки очереди. Часть загрузок пока ожидает.');
    if (report && report.capacity_reached) warnings.push('Достигнут лимит обработки. Новые файлы пока не объявляются готовыми.');
    const checking = autoCleanerRequest || Boolean(state && state.job && state.job.kind === 'server-auto-cleaner' && state.job.state === 'running');
    const healthy = !closing && !checking && Boolean(report && status.installed === true && status.enabled === true
      && status.running === true && status.user_session === true && status.auto_cleaner === true && !warnings.length);
    let message = 'Свежего отчёта пока нет. Дождитесь проверки.';
    let guidance = 'Служба работает внутри удалённой Workstation; её состояние проверяется отдельно от содержимого файлов.';
    if (closing) message = 'Приложение завершает работу. Новые проверки не запускаются.';
    else if (!connected) {
      message = 'Сначала подключите мастер к своему серверу.';
      guidance = 'На этапе 8 подключитесь к тому же серверу и восстановите наблюдение установки. Новую установку поверх нужных данных не запускайте.';
    } else if (!installed) {
      message = 'Сначала проверьте итог установки сервера.';
      guidance = 'На этапе 8 восстановите наблюдение уже начатой установки, затем вернитесь к автоочистке.';
    } else if (checking) message = 'Проверяю автоочистку Workstation…';
    else if (status && status.user_session === false) {
      message = 'Откройте обычный рабочий стол Workstation.';
      guidance = 'Нужен режим USER Session. После запуска рабочего стола повторите проверку автоочистки.';
    } else if (healthy) message = '✓ Автоочистка Workstation работает.';
    else if (report) message = 'Работа автоочистки пока не подтверждена. Прочитайте результат проверки.';
    $('auto-cleaner-state').textContent = message;
    $('auto-cleaner-state').classList.toggle('ready', healthy);
    $('auto-cleaner-guidance').textContent = guidance;
    $('auto-cleaner-check').disabled = busy || closing || phoneRequestPending || autoCleanerRequest || !connected || !installed;
    $('auto-cleaner-connect').hidden = connected && installed;
    $('auto-cleaner-connect').dataset.actionIndex = connected ? '3' : '1';
    $('auto-cleaner-connect').textContent = connected ? 'К проверке установки →' : 'К подключению сервера →';
    $('auto-cleaner-session').hidden = !connected || !installed || !status || status.user_session !== false;
    const count = (key) => report && Number.isSafeInteger(report[key]) && report[key] >= 0 ? report[key].toLocaleString('ru-RU') : '—';
    ['pending', 'processing', 'cleaned', 'failed', 'unsupported', 'downloading'].forEach((key) => { $('auto-cleaner-' + key).textContent = count(key); });
    $('auto-cleaner-ready-count').textContent = count('cleaned');
    const last = {waiting:'Ожидаю новые законченные загрузки.', processing:'Создаётся обработанная копия.', cleaned:'Создана обработанная копия.', failed:'Последняя обработка завершилась ошибкой.', unsupported:'Последний формат не поддерживается.', changed:'Файл ещё меняется: автоочистка ждёт стабильную загрузку.'};
    $('auto-cleaner-last-result').textContent = report && Object.prototype.hasOwnProperty.call(last, report.last_result) ? last[report.last_result] : 'Жду свежий отчёт.';
    $('auto-cleaner-limits').textContent = warnings.join(' ');
  }
  function canCheckAutoCleaner() {
    return !closed && nonce && !document.hidden && !submittingJob && activeStep === 13 && state && !state.closing
      && state.server_connected && state.server_installed && !phoneRequestPending && !autoCleanerRequest
      && !(state.job && state.job.state === 'running');
  }
  async function requestAutoCleaner() {
    if (!canCheckAutoCleaner()) return;
    autoCleanerRequest = true;
    nextAutoCleanerCheck = Date.now() + 15000;
    renderAutoCleaner(true);
    try { return await perform('/api/server/action', {action: 'auto-cleaner'}); }
    finally {
      autoCleanerRequest = false;
      if (state && !closed) render(state);
    }
  }
  function checkAutoCleanerWhenVisible() {
    if (autoCleanerScheduled || Date.now() < nextAutoCleanerCheck || !canCheckAutoCleaner()) return;
    autoCleanerScheduled = true;
    setTimeout(async () => {
      try { if (canCheckAutoCleaner()) await requestAutoCleaner(); }
      finally { autoCleanerScheduled = false; }
    }, 0);
  }
  function canCheckReadiness() {
    return !closed && nonce && !document.hidden && !submittingJob && !phoneRequestPending && !autoCleanerRequest && activeStep === 9
      && innerPositions.get(9) === 5 && state && state.server_connected
      && !state.closing
      && state.server_installed && !state.guest_ready
      && !(state.job && state.job.state === 'running');
  }
  function checkReadinessWhenVisible() {
    if (readinessRequest || Date.now() < nextReadyCheck || !canCheckReadiness()) return;
    readinessRequest = true;
    nextReadyCheck = Date.now() + 15000;
    // Only observe the already installed server while its readiness action is open.
    setTimeout(async () => {
      try { if (canCheckReadiness()) await perform('/api/server/action', {action: 'status'}); }
      finally { readinessRequest = false; }
    }, 0);
  }
  async function disks() {
    clearError();
    try {
      const result = await api('/api/usb/disks');
      const select = $('usb-disk');
      select.replaceChildren();
      const empty = document.createElement('option');
      empty.value = ''; empty.textContent = result.disks.length ? 'Выберите флешку — проверьте размер' : 'Подходящих флешек не найдено';
      select.appendChild(empty);
      for (const disk of result.disks) {
        const option = document.createElement('option');
        option.value = disk.id;
        option.textContent = `${disk.name} · ${(disk.size_bytes / 1e9).toFixed(1)} ГБ`;
        select.appendChild(option);
      }
      $('erase-confirmation').value = '';
      $('disk-hint').textContent = result.disks.length ? 'Сверьте название и размер со своей флешкой. При смене носителя обновите список.' : 'Подключите флешку и повторите. Неоднозначные и системные диски не предлагаются.';
    } catch (error) { showError(error.message); }
  }
  async function showCard() {
    clearError();
    const version = ++cardVersion;
    try {
      const result = await api('/api/secrets');
      if (version !== cardVersion || closed || document.hidden || activeStep !== 9) return;
      const fields = $('secret-fields'); fields.replaceChildren();
      const labels = {url:'Адрес кабинета — открыть в Tor Browser', login:'Имя входа — из карточки сервера', password:'Пароль кабинета', totp_secret:'Ключ кодов — добавить в аутентификатор'};
      Object.entries(labels).forEach(([key, title]) => {
        const row = document.createElement('div'); row.className = 'secret-row';
        const group = document.createElement('div');
        const label = document.createElement('label'); label.textContent = title; label.htmlFor = `card-${key}`;
        const input = document.createElement('input'); input.id = `card-${key}`; input.value = result.credentials[key]; input.readOnly = true; input.autocomplete = 'off'; input.spellcheck = false;
        if (key === 'password' || key === 'totp_secret') {
          const wrapper = document.createElement('div'); wrapper.className = 'secret-input'; input.type = 'password';
          const toggle = document.createElement('button'); toggle.className = 'reveal'; toggle.type = 'button'; toggle.textContent = 'Показать'; toggle.setAttribute('aria-label', `Показать: ${title}`); toggle.setAttribute('aria-pressed', 'false');
          toggle.addEventListener('click', () => toggleSecret(input, toggle)); wrapper.append(input, toggle); group.append(label, wrapper);
        } else { group.append(label, input); }
        const button = document.createElement('button'); button.className = 'button small secondary'; button.type = 'button'; button.textContent = 'Копировать'; button.setAttribute('aria-label', `Копировать: ${title}`); button.addEventListener('click', () => copy(input.value));
        row.append(group, button); fields.appendChild(row);
      });
      // The response object is not retained; credentials live only in visible fields.
      Object.keys(result.credentials).forEach((key) => { result.credentials[key] = ''; });
      $('secret-card').hidden = false; $('show-card').hidden = true;
      $('card-url').focus();
    } catch (error) { if (version === cardVersion) showError(error.message); }
  }
  async function prepareHandoff() {
    clearError();
    const version = ++handoffVersion;
    $('handoff-note').value = '';
    $('handoff-panel').hidden = true;
    try {
      const result = await api('/api/access-note');
      if (version !== handoffVersion || closed || !nonce) return;
      if (typeof result.text !== 'string' || !result.text || result.text.length > 16000) throw new Error('Не удалось подготовить памятку. Получите карточку с сервера и повторите.');
      $('handoff-note').value = result.text;
      $('handoff-panel').hidden = false;
      $('handoff-note').focus();
      $('handoff-note').setSelectionRange(0, 0);
      $('handoff-note').scrollTop = 0;
    } catch (error) { if (version === handoffVersion) showError(error.message); }
  }
  function toggleSecret(input, button) {
    const show = input.type === 'password'; input.type = show ? 'text' : 'password';
    button.textContent = show ? 'Скрыть' : 'Показать'; button.setAttribute('aria-pressed', String(show));
  }

  const dailyGuides = Object.freeze({
    windows: {name: 'Windows', advice: 'Используйте Tor Browser из комплекта в обычной Windows. Telegram открывается на удалённом рабочем столе.', steps: [
      {title: 'Подготовьте Tor Browser на этом компьютере.', text: 'Запустите OnionDesk в Windows. На этапе 1 мастер подготовит официальный Tor Browser из комплекта. Если он уже подготовлен, переходите к следующей подсказке.', stage: 1, action: 1, stageLabel: 'Открыть подготовку Tor Browser'},
      {title: 'Завершите установку Windows.', text: 'Если открылся установщик Tor Browser, завершите его сами. Системные разрешения подтверждаете вы. После установки OnionDesk открывайте его ярлыком: нужные файлы комплекта уже скопированы в установленную программу.', source: 'https://www.torproject.org/download/', sourceLabel: 'Копировать официальный Tor Browser для Windows'},
      {title: 'Подключитесь в Tor Browser.', text: 'Откройте подготовленный Tor Browser и нажмите Connect / Подключиться. Дождитесь сообщения о соединении. При блокировке используйте настройку мостов Tor в браузере.'},
      {title: 'Продолжите к адресу кабинета.', text: 'Оставьте Tor Browser открытым. В следующем действии этого этапа вставьте в него свой сохранённый адрес кабинета. Telegram устанавливается на сервере; локальный Telegram для этого входа не нужен.'}
    ]},
    macos: {name: 'macOS', advice: 'Для входа через Tor Browser на этом Mac дополнительный компьютер не нужен; этапы 5 и 11 пропустите. На Apple Silicon флешку Tails можно подготовить для другого совместимого компьютера Intel или AMD. OnionDesk для Mac работает на Apple Silicon с macOS 15 или новее; на Mac с Intel установите официальный Tor Browser вручную.', steps: [
      {title: 'Выберите подготовку для своего Mac.', text: 'На Mac с Apple Silicon и macOS 15 или новее откройте OnionDesk: этап 1 подготовит Tor Browser из комплекта. На Mac с Intel пропустите подготовку в мастере и перейдите к следующей подсказке с официальной загрузкой браузера.', stage: 1, action: 1, stageLabel: 'Подготовка для Mac с Apple Silicon'},
      {title: 'Установите или откройте Tor Browser.', text: 'На Mac с Intel скачайте Tor Browser для macOS по официальному адресу ниже и установите его по инструкции Tor Project. На совместимом Mac с Apple Silicon откройте браузер, подготовленный на этапе 1. Системные разрешения подтверждаете вы.', source: 'https://www.torproject.org/download/', sourceLabel: 'Копировать официальный Tor Browser для macOS'},
      {title: 'Дождитесь соединения Tor.', text: 'В Tor Browser нажмите Connect / Подключиться. Дождитесь соединения; при блокировке настройте мосты в браузере.'},
      {title: 'Откройте свой удалённый кабинет.', text: 'Переходите к следующему действию и используйте сохранённый адрес именно своего кабинета в Tor Browser. Работа с Telegram будет происходить на сервере.'}
    ]},
    linux: {name: 'Linux', advice: 'Tor Browser в этом комплекте предназначен для Linux на 64-битном Intel или AMD. Для Linux ARM64 выберите вход с телефона или с другого совместимого компьютера.', steps: [
      {title: 'Подготовьте Tor Browser в Linux.', text: 'На компьютере с 64-битным Intel или AMD откройте OnionDesk в обычном Linux. На этапе 1 мастер подготовит официальный Tor Browser из комплекта. Для Linux ARM64 эта подготовка не подходит.', stage: 1, action: 1, stageLabel: 'Подготовка для Linux на Intel/AMD'},
      {title: 'Запустите подготовленный Tor Browser.', text: 'Откройте браузер его подготовленным значком. Если система просит разрешить запуск файла, сначала убедитесь, что это файл из проверенного комплекта. Разрешение системы даёте вы.', source: 'https://www.torproject.org/download/', sourceLabel: 'Копировать официальный Tor Browser для Linux'},
      {title: 'Подключитесь к Tor.', text: 'Нажмите Connect / Подключиться в Tor Browser. Дождитесь соединения. Если оно не устанавливается, используйте штатную настройку мостов Tor.'},
      {title: 'Продолжите к своему адресу.', text: 'В следующем действии откройте сохранённый адрес кабинета в этом Tor Browser. Telegram остаётся на удалённом рабочем столе; устанавливать его в локальный Linux для входа не требуется.'}
    ]},
    tails: {name: 'Tails', advice: 'Сначала в обычной системе настройте сервер на этапах 8–10 и сохраните адрес и данные входа отдельно. Tails сама не создаёт сервер. Android и iPhone не могут загрузить Tails.', steps: [
      {title: 'Загрузитесь с подготовленной флешки.', text: 'Для Tails нужен совместимый компьютер Intel или AMD — можно использовать тот же компьютер, где был открыт мастер. До выключения откройте PDF-инструкцию на телефоне или распечатайте этап 11: мастер в Tails автоматически не продолжится. Если вы ещё не загрузились с USB, откройте этап 11.', stage: 11, action: 0, stageLabel: 'Открыть вход через Tails'},
      {title: 'Подключите сеть и Tor Connection.', text: 'В Tails подключитесь к своей сети. Откройте Tor Connection и дождитесь соединения; при блокировке следуйте подсказкам мостов. VPN внутри Tails здесь не настраивается.', source: 'https://tails.net/doc/', sourceLabel: 'Копировать официальную помощь Tails'},
      {title: 'Откройте Tor Browser в Tails.', text: 'После подтверждения Tor откройте встроенный Tor Browser. Памятку со второго USB откройте через «Файлы» и скопируйте полный onion-адрес в браузер. С бумажной памятки введите полный адрес вручную — файл и второй USB не нужны. Имя, пароль и ключ приложения кодов храните отдельно от памятки.'}
    ]},
    android_usb: {name: 'Android · USB', advice: 'Подготовка через USB идёт с этого компьютера. Телефон остаётся под вашим контролем; разрешения и подключение Tor выполняете вы.', steps: [
      {title: 'Подключите свой Android кабелем.', text: 'Разблокируйте телефон и подключите его к этому доверенному компьютеру USB-кабелем, который передаёт данные. Кабель только для зарядки не подойдёт.'},
      {title: 'Откройте параметры разработчика.', text: 'На телефоне откройте Настройки → О телефоне → Номер сборки. Обычно по номеру сборки нужно нажать семь раз и подтвердить действие своим кодом телефона. Названия могут отличаться у вашей модели.', source: 'https://developer.android.com/studio/debug/dev-options', sourceLabel: 'Копировать официальную инструкцию Android'},
      {title: 'Разрешите USB-подключение сами.', text: 'В параметрах разработчика включите «Отладка по USB». На экране телефона подтвердите запрос только от этого доверенного компьютера. Мастер не подтверждает разрешение за вас. Если запроса ещё нет, следующий поиск устройств может его вызвать.'},
      {title: 'Найдите подключённый телефон.', text: 'Нажмите кнопку поиска на компьютере. Если Android показывает запрос разрешения, подтвердите его на телефоне и повторите поиск. Поиск не устанавливает приложения и не подтверждает соединение Tor.'},
      {title: 'Выберите свой Android из списка.', text: 'Сверьте найденное устройство со своим телефоном и выберите его сами. Пункты без подтверждённого USB-разрешения недоступны. Если телефона нет, вернитесь к поиску.'},
      {title: 'Установите официальный Tor Browser.', text: 'Нажмите кнопку установки для выбранного Android. Мастер установит проверенный официальный Tor Browser. Если Android требует дополнительное разрешение, подтвердите его сами. Дождитесь результата операции; установка ещё не подключает Tor.'},
      {title: 'Подключитесь к Tor на телефоне.', text: 'На Android откройте Tor Browser и нажмите Connect / Подключиться. При блокировке настройте мосты в браузере и дождитесь сообщения о соединении. Затем в этом браузере откройте только свой удалённый кабинет. Локальный Telegram для этого не устанавливайте.'},
      {title: 'Закройте USB-доступ после установки.', text: 'Нажмите «Завершить USB-подключение» на компьютере. На телефоне выключите «Отладку по USB», отзовите ранее выданные USB-разрешения компьютерам и отсоедините кабель. Действия на телефоне мастер не проверяет.'}
    ]},
    android_phone: {name: 'Android · без USB', advice: 'Этот путь выполняется на самом Android. Разрешать USB-отладку и подключать телефон к компьютеру не нужно.', steps: [
      {title: 'Откройте официальный сайт на Android.', text: 'На самом телефоне откройте torproject.org/download и выберите Tor Browser for Android. Кнопка ниже копирует официальный адрес на этом устройстве; при необходимости введите его на телефоне вручную.', source: 'https://download.torproject.org/tor-browser-for-android/', sourceLabel: 'Копировать Tor Browser для Android'},
      {title: 'Установите Tor Browser на телефоне.', text: 'Перейдите по официальной ссылке Tor Project в магазин приложений или скачайте указанный там файл для Android. Системные разрешения подтверждаете вы. Не устанавливайте браузер по случайной ссылке из чата.', source: 'https://download.torproject.org/tor-browser-for-android/', sourceLabel: 'Копировать официальную загрузку для Android'},
      {title: 'Нажмите Connect в Tor Browser.', text: 'Откройте Tor Browser на Android, нажмите Connect / Подключиться и дождитесь соединения. При блокировке настройте мосты внутри браузера.'},
      {title: 'Продолжите к удалённому кабинету.', text: 'В следующем действии откройте свой сохранённый адрес в Tor Browser на Android. Telegram остаётся на сервере; устанавливать локальный Telegram для доступа к кабинету не нужно.'}
    ]},
    iphone: {name: 'iPhone', advice: 'На iPhone установите Orbot и Onion Browser из App Store. Подключение и разрешения iOS подтверждаете сами.', steps: [
      {title: 'Установите официальный Orbot.', text: 'На iPhone откройте официальную страницу Orbot в App Store и установите приложение. Проверьте название и издателя перед загрузкой.', source: 'https://apps.apple.com/us/app/orbot/id1609461599', sourceLabel: 'Копировать Orbot в App Store'},
      {title: 'Разрешите Orbot подключение в iOS.', text: 'Откройте Orbot и запустите соединение. Если iOS просит добавить VPN-конфигурацию, прочитайте системное окно и подтвердите его сами. Мастер не нажимает разрешения за вас. Дождитесь соединения Orbot.'},
      {title: 'Установите официальный Onion Browser.', text: 'На iPhone откройте официальную страницу Onion Browser в App Store и установите приложение. Проверьте название и издателя перед загрузкой.', source: 'https://apps.apple.com/us/app/onion-browser/id519296448', sourceLabel: 'Копировать Onion Browser в App Store'},
      {title: 'Откройте Onion Browser после Orbot.', text: 'Оставьте Orbot подключённым и откройте Onion Browser. Следуйте его подсказкам подключения. Возможности и ограничения iPhone отличаются от настольного Tor Browser.'},
      {title: 'Откройте свой удалённый кабинет.', text: 'В следующем действии вставьте свой сохранённый адрес кабинета в Onion Browser. Telegram будет работать на сервере; локальный Telegram для этого входа не требуется.'}
    ]}
  });
  function dailyGuideKey() {
    const platform = $('daily-device').value;
    if (platform === 'android') {
      const method = $('daily-method').value;
      return ['usb', 'phone'].includes(method) ? `android_${method}` : '';
    }
    return ['windows', 'macos', 'linux', 'tails', 'iphone'].includes(platform) ? platform : '';
  }
  function drawDailyGuide(focus = false) {
    const key = dailyGuideKey();
    const guide = dailyGuides[key];
    $('daily-android-method').hidden = $('daily-device').value !== 'android';
    $('daily-guide').hidden = !guide;
    $('daily-device-advice').hidden = !guide;
    const mentor = document.querySelector('[data-art-key="g12-s01"] > .mentor-card');
    if (mentor) mentor.hidden = Boolean(guide);
    ['daily-open-stage', 'daily-source', 'daily-phone-find', 'daily-phone-choose', 'daily-phone-install', 'daily-phone-cleanup', 'daily-phone-status', 'daily-usb-help'].forEach((id) => { $(id).hidden = true; });
    $('daily-source').dataset.copy = '';
    $('daily-open-stage').dataset.actionGo = '-1';
    $('daily-open-stage').dataset.actionIndex = '-1';
    $('daily-guide-title').textContent = '';
    $('daily-guide-text').textContent = '';
    $('daily-guide-position').textContent = '';
    if (!guide) {
      $('daily-device-advice').textContent = $('daily-device').value === 'android'
        ? 'Выберите известный способ подготовки Android: через USB или без USB.'
        : 'Выберите устройство из списка. Для неизвестного выбора инструкция не показана.';
      $('daily-guide-back').disabled = true;
      $('daily-guide-next').disabled = true;
      if (focus) showStepStart(document.querySelector('[data-page="12"]'));
      return;
    }
    const index = Math.max(0, Math.min(guide.steps.length - 1, dailyPositions.get(key) || 0));
    dailyPositions.set(key, index);
    const step = guide.steps[index];
    $('daily-device-advice').textContent = guide.advice;
    $('daily-guide-title').textContent = step.title;
    const split = step.text.match(/^(.+?[.!?])(?:\s+|$)([\s\S]*)$/);
    $('daily-mentor-quote').textContent = split ? split[1] : step.text;
    $('daily-guide-text').textContent = split ? split[2] : '';
    document.querySelector('[data-art-key="g12-s01"] > .mentor-card').hidden = true;
    updateDailyMark();
    $('daily-guide-position').textContent = `${guide.name} · шаг ${index + 1} из ${guide.steps.length}`;
    $('daily-guide-progress').max = guide.steps.length;
    $('daily-guide-progress').value = index + 1;
    $('daily-guide-back').disabled = index === 0;
    $('daily-guide-next').disabled = index === guide.steps.length - 1;
    if (step.source) {
      $('daily-source').hidden = false;
      $('daily-source').dataset.copy = step.source;
      $('daily-source').textContent = step.sourceLabel;
    }
    if (Number.isInteger(step.stage)) {
      $('daily-open-stage').hidden = false;
      $('daily-open-stage').dataset.actionGo = String(step.stage);
      $('daily-open-stage').dataset.actionIndex = String(step.action);
      $('daily-open-stage').textContent = step.stageLabel;
    }
    if (key === 'android_usb') {
      $('daily-phone-find').hidden = index !== 3;
      $('daily-phone-choose').hidden = index !== 4;
      $('daily-phone-install').hidden = index !== 5;
      $('daily-phone-cleanup').hidden = index !== 7;
      $('daily-phone-status').hidden = false;
      $('daily-usb-help').hidden = false;
    }
    renderPhone(Boolean(state && state.job && state.job.state === 'running'));
    if (focus) showStepStart(document.querySelector('[data-page="12"]'));
  }
  function renderPhone(busy) {
    const phone = state && state.phone || {};
    const devices = Array.isArray(phone.devices) ? phone.devices.filter((device) => device
      && typeof device.id === 'string' && device.id.length > 0 && device.id.length <= 256
      && typeof device.label === 'string' && typeof device.state === 'string') : [];
    const select = $('phone-device');
    const catalog = JSON.stringify(devices.map((device) => [device.id, device.state, device.label]));
    if (select.dataset.catalog !== catalog) {
      const previous = select.value;
      select.replaceChildren(new Option(devices.length ? 'Выберите свой Android' : 'Сначала найдите подключённый телефон', ''));
      devices.forEach((device) => {
        const note = device.state === 'device' ? 'USB-разрешение получено'
          : device.state === 'unauthorized' ? 'подтвердите USB-разрешение на телефоне'
          : device.state === 'offline' ? 'связь с телефоном недоступна' : 'устройство пока недоступно';
        const option = new Option(`${device.label} · ${note}`, device.id);
        option.disabled = device.state !== 'device';
        select.add(option);
      });
      select.value = devices.some((device) => device.id === previous && device.state === 'device') ? previous : '';
      select.dataset.catalog = catalog;
    }
    const selected = devices.find((device) => device.id === select.value && device.state === 'device');
    const unavailable = phone.available !== true;
    const waiting = busy || submittingJob || phoneRequestPending || autoCleanerRequest || closed || Boolean(state && state.closing);
    $('phone-list').disabled = waiting || unavailable;
    $('phone-device').disabled = waiting || unavailable;
    $('phone-install').disabled = waiting || unavailable || phone.session_open !== true || !selected;
    $('phone-selected-device').textContent = selected ? `Будет использован: ${selected.label}.` : 'Сначала выберите свой Android на предыдущем шаге подсказки.';
    $('phone-state').textContent = typeof phone.message === 'string' && phone.message
      ? phone.message : 'USB-подготовка пока недоступна. Можно выбрать способ «Без USB — на самом телефоне».';
    $('phone-guidance').textContent = typeof phone.guidance === 'string' ? phone.guidance
      : Array.isArray(phone.guidance) ? phone.guidance.filter((item) => typeof item === 'string').join(' ') : '';
    $('phone-installed').textContent = phone.installed === true
      ? 'Tor Browser установлен. Подключение Tor выполните и проверьте сами на экране телефона.'
      : 'Установка браузера пока не подтверждена. Состояние Tor на телефоне этот мастер не проверяет.';
    const cleanup = Boolean(phone.session_open || phone.cleanup_required);
    $('phone-session-panel').hidden = !cleanup;
    $('phone-session-state').textContent = phoneRequestPending ? 'Дождитесь завершения текущей операции USB.'
      : 'После подготовки Android завершите USB-подключение на компьютере. Разрешения на телефоне нужно отключить отдельно.';
    $('phone-close').disabled = waiting || !cleanup;
    $('phone-close-guide').disabled = waiting || !cleanup;
  }
  function dailyUsbAction(index) {
    return activeStep === 12 && innerPositions.get(12) === 0 && dailyGuideKey() === 'android_usb'
      && dailyPositions.get('android_usb') === index;
  }
  async function performPhone(path, data = {}) {
    if (closed || document.hidden || phoneRequestPending || autoCleanerRequest || !state || state.closing || (state.job && state.job.state === 'running')) return;
    phoneRequestPending = true;
    renderPhone(false);
    try { return await perform(path, data); }
    finally {
      phoneRequestPending = false;
      if (state && !closed) render(state);
    }
  }

  function wipeWalletSecrets(forget = true, clearDetails = true) {
    walletVersion += 1;
    clearTimeout(walletTimer);
    walletChallenge = null;
    $('wallet-words').replaceChildren();
    $('wallet-seed-panel').hidden = true;
    $('wallet-backup-state').classList.remove('backup-confirmed');
    ['wallet-password', 'wallet-password-confirm', 'wallet-unlock-password', 'wallet-reveal-password',
      'wallet-answer-0', 'wallet-answer-1', 'wallet-answer-2'].forEach((id) => { $(id).value = ''; });
    for (let index = 0; index < 3; index++) $('wallet-answer-label-' + index).textContent = 'Слово';
    if (clearDetails) {
      walletDetails = [];
      $('wallet-select').replaceChildren(new Option('Сначала загрузите список', ''));
      $('wallet-receive-select').replaceChildren();
      $('wallet-address').value = '';
      $('wallet-receive-backup').textContent = '';
      $('wallet-receive-panel').hidden = true;
    }
    // Forgetting never sends secrets, and is restricted to this launch's loopback API.
    if (forget && nonce && !closed && !(state && state.closing)) api('/api/wallet/forget', {}).catch((error) => {
      if (!closed && !document.hidden) showError(error.message);
    });
  }
  function renderWalletCorner(wallet, vaults, busy) {
    let mode = 'loading';
    let title = 'Проверяю файлы…';
    let detail = 'Кошелёк хранится на этом компьютере.';
    if (wallet.available === false) {
      mode = 'unavailable'; title = 'Недоступен';
      detail = 'Причина и дальнейшие действия — на этапе кошелька.';
    } else if (wallet.available) {
      if (wallet.workspace_open) {
        mode = 'open'; title = wallet.has_wallet ? 'Открыт' : 'Хранилище открыто';
        detail = wallet.has_wallet ? 'Состояние бумажной копии пока неизвестно.' : 'Можно создать кошелёк в открытом хранилище.';
        if (wallet.has_wallet && wallet.backup_confirmed === true) {
          mode = 'confirmed'; title = 'Открыт · копия ✓'; detail = '✓ Бумажная копия слов проверена.';
        } else if (wallet.has_wallet && wallet.backup_confirmed === false) {
          mode = 'unconfirmed'; title = 'Сохраните 25 слов'; detail = 'Кошелёк открыт. Бумажная копия ещё не проверена.';
        }
      } else if (vaults.length) {
        mode = 'closed'; title = 'Закрыт';
        detail = vaults.length === 1 ? `На этом компьютере: ${vaults[0].label}` : `Хранилищ на этом компьютере: ${vaults.length}. Выберите своё при открытии.`;
      } else {
        mode = 'new'; title = 'Ещё не создан';
        detail = 'Создайте его и сохраните бумажную копию 25 слов.';
      }
    }
    $('wallet-corner').dataset.state = mode;
    $('wallet-corner-state').textContent = title;
    $('wallet-corner-detail').textContent = detail;
    $('wallet-corner-open').textContent = mode === 'new' ? 'Создать' : mode === 'unavailable' ? 'Подробнее' : 'Открыть';
    $('wallet-corner-open').disabled = busy || mode === 'loading';
    const canFindWallet = Boolean(wallet.has_wallet || wallet.pending_seed || vaults.length);
    $('wallet-corner-words').disabled = busy || !wallet.available || !canFindWallet;
    $('wallet-corner-receive').disabled = busy || !wallet.available || !canFindWallet;
    $('wallet-corner-lock').disabled = busy || walletLockPending || !wallet.workspace_open;
  }
  function renderWallet(busy) {
    busy = busy || submittingJob || phoneRequestPending || autoCleanerRequest || Boolean(state && state.closing);
    const wallet = state.wallet || {};
    $('wallet-state').textContent = wallet.message || 'Состояние хранилища пока не получено.';
    $('wallet-state').classList.toggle('ready', Boolean(wallet.workspace_open));
    $('wallet-seed').disabled = busy || !wallet.pending_seed || !$('wallet-seed-panel').hidden;
    $('wallet-create').disabled = busy || !wallet.available;
    $('wallet-lock').disabled = busy || walletLockPending || !wallet.workspace_open;
    const vaults = Array.isArray(wallet.vaults) ? wallet.vaults : [];
    renderWalletCorner(wallet, vaults, busy);
    const select = $('wallet-vault');
    const previous = select.value;
    const fingerprint = JSON.stringify(vaults.map((vault) => [vault.id, vault.label]));
    if (select.dataset.catalog !== fingerprint) {
      select.replaceChildren(new Option(vaults.length ? 'Выберите своё хранилище' : 'Хранилища ещё не найдены', ''));
      vaults.forEach((vault) => {
        if (typeof vault.id === 'string' && typeof vault.label === 'string') select.add(new Option(vault.label, vault.id));
      });
      select.value = previous;
      select.dataset.catalog = fingerprint;
    }
    $('wallet-unlock').disabled = busy || !select.value;
    $('wallet-reveal').disabled = busy || !$('wallet-select').value;
    const job = state.job;
    if (!job || !job.kind.startsWith('wallet-') || job.state === 'running') return;
    const key = `${job.id}:${job.state}`;
    if (lastWalletJob === key) return;
    lastWalletJob = key;
    if (job.kind === 'wallet-confirm') {
      wipeWalletSecrets();
      $('wallet-backup-state').textContent = job.state === 'done'
        ? '✓ Три слова совпали. Резервная копия подтверждена; полную бумажную фразу храните отдельно.'
        : 'Проверка не подтверждена. Для повторной попытки снова подготовьте фразу с паролем.';
      $('wallet-backup-state').classList.toggle('backup-confirmed', job.state === 'done');
    } else if (job.kind === 'wallet-lock' && job.state === 'done') {
      wipeWalletSecrets(false);
      $('wallet-state').textContent = '✓ Рабочее хранилище кошелька закрыто.';
    }
  }
  function walletShortcut(step, index, action) {
    if (closed || document.hidden || !state || state.closing || (state.job && state.job.state === 'running')) return;
    const wallet = state.wallet || {};
    const sameGoal = activeStep === step;
    // Keep an unopened pending phrase when moving within its current goal.
    // Crossing goals still uses the normal secret wipe and explicit reveal flow.
    if (!sameGoal) go(step);
    const page = document.querySelector(`[data-page="${step}"]`);
    drawInner(page, index);
    if (action === 'open' && (wallet.vaults || []).length) {
      $('wallet-existing').open = true;
    } else if (action === 'words' && !(sameGoal && wallet.pending_seed)) {
      $('wallet-reveal-help').open = true;
    }
    collapseWalletControls();
    showStepStart(page);
  }
  async function lockWallet() {
    if (closed || document.hidden || walletLockPending || !state || state.closing || !state.wallet || !state.wallet.workspace_open || (state.job && state.job.state === 'running')) return;
    walletLockPending = true;
    $('wallet-lock').disabled = true;
    $('wallet-corner-lock').disabled = true;
    wipeWalletSecrets(false);
    try { await perform('/api/wallet/lock'); }
    finally {
      walletLockPending = false;
      if (state && !closed) renderWallet(Boolean(state.job && state.job.state === 'running'));
    }
  }
  function submitWalletPassword(path, ids, extra = {}) {
    clearError();
    const password = $(ids[0]).value;
    const matches = ids.length < 2 || password === $(ids[1]).value;
    const data = {...extra, password};
    ids.forEach((id) => { $(id).value = ''; });
    if (!matches || password.length < 12 || password.length > 256 || password.includes('\0')) {
      data.password = '';
      showError(!matches ? 'Пароли кошелька не совпали. Введите их заново.' : 'Пароль кошелька должен содержать от 12 до 256 символов.');
      return;
    }
    wipeWalletSecrets(false, false);
    if (path === '/api/wallet/create' || path === '/api/wallet/unlock') {
      $('wallet-backup-state').textContent = 'Резервная копия выбранного кошелька пока не проверена в этом представлении.';
    }
    const operation = perform(path, data);
    data.password = '';
    return operation;
  }
  async function loadWallets(receive = false) {
    const step = receive ? 3 : 2;
    if (activeStep !== step || document.hidden || closed) return;
    const version = walletVersion;
    clearError();
    try {
      const result = await api('/api/wallet/list');
      if (version !== walletVersion || activeStep !== step || document.hidden || closed) return;
      if (!Array.isArray(result.wallets)) throw new Error('Мастер вернул неизвестный список кошельков.');
      walletDetails = result.wallets.filter((wallet) => wallet && typeof wallet.wallet_id === 'string'
        && wallet.wallet_id.length <= 100 && wallet.network === 'mainnet'
        && typeof wallet.address === 'string' && /^[48][1-9A-HJ-NP-Za-km-z]{94,105}$/.test(wallet.address));
      const select = $(receive ? 'wallet-receive-select' : 'wallet-select');
      select.replaceChildren();
      walletDetails.forEach((wallet, index) => select.add(new Option(`Кошелёк ${index + 1} · mainnet`, wallet.wallet_id)));
      if (!walletDetails.length) {
        select.add(new Option('Нет кошельков в открытом хранилище', ''));
        if (receive) $('wallet-receive-panel').hidden = true;
        throw new Error('Сначала откройте своё хранилище кошелька на этапе 2.');
      }
      if (receive) { $('wallet-receive-panel').hidden = false; updateWalletAddress(); }
      else $('wallet-reveal').disabled = Boolean(state && state.job && state.job.state === 'running');
    } catch (error) { if (version === walletVersion) showError(error.message); }
  }
  function updateWalletAddress() {
    if (activeStep !== 3 || document.hidden) return;
    const wallet = walletDetails.find((item) => item.wallet_id === $('wallet-receive-select').value);
    $('wallet-address').value = wallet ? wallet.address : '';
    $('wallet-receive-backup').textContent = wallet
      ? (wallet.backup_confirmed ? 'Резервная копия подтверждена в кошельке.' : 'Резервная копия ещё не подтверждена. Сначала сохраните и проверьте фразу на этапе 2.') : '';
  }
  async function showWalletSeed() {
    if (closed || document.hidden || activeStep !== 2) return;
    const version = ++walletVersion;
    clearError();
    $('wallet-seed').disabled = true;
    let result;
    try {
      result = await api('/api/wallet/seed', {});
      if (version !== walletVersion || closed || document.hidden || activeStep !== 2) return;
      if (!Array.isArray(result.words) || result.words.length !== 25
          || !result.words.every((word) => typeof word === 'string' && /^[a-zA-Z]{1,32}$/.test(word))
          || !Array.isArray(result.positions) || result.positions.length !== 3
          || new Set(result.positions).size !== 3 || !result.positions.every((position) => Number.isInteger(position) && position >= 1 && position <= 25)
          || typeof result.wallet_id !== 'string' || result.wallet_id.length > 100
          || typeof result.challenge !== 'string' || result.challenge.length > 200) throw new Error('Некорректный ответ фразы. Слова не показаны; повторно введите пароль.');
      walletChallenge = {wallet_id: result.wallet_id, challenge: result.challenge};
      const words = result.words.map((word, index) => {
        const item = document.createElement('li');
        const number = document.createElement('span'); number.textContent = String(index + 1).padStart(2, '0') + '. ';
        item.append(number, document.createTextNode(word));
        return item;
      });
      $('wallet-words').replaceChildren(...words);
      result.positions.forEach((position, index) => { $('wallet-answer-label-' + index).textContent = `Слово № ${position}`; });
      $('wallet-seed-panel').hidden = false;
      $('wallet-backup-state').textContent = 'Слова показаны временно. Перепишите по номерам и проверьте бумажную копию.';
      $('wallet-answer-0').focus({preventScroll: true});
      walletTimer = setTimeout(() => {
        wipeWalletSecrets();
        $('wallet-backup-state').textContent = 'Время показа истекло. Для повторного просмотра снова введите пароль.';
      }, 170000);
    } catch (error) {
      if (version === walletVersion) { wipeWalletSecrets(); showError(error.message); }
    } finally {
      if (result && Array.isArray(result.words)) result.words.fill('');
    }
  }
  const markedActions = new Set();
  const markedDaily = new Set();
  const mentorTips = Object.freeze({
    'g00-s01': "Проследите маршрут: ваше устройство → Tor → удалённый рабочий стол.",
    'g00-s02': "Сверьте определённую систему и выберите Tor Browser в обычной системе либо Tails на совместимом компьютере.",
    'g01-s01': "Для первого входа оставьте «Tor с мостами» и нажмите «Следующее действие».",
    'g01-s02': "Нажмите «Подготовить и открыть Tor Browser»; в Windows завершите открывшийся установщик сами.",
    'g01-s03': "В Tor Browser нажмите Connect / Подключиться, дождитесь соединения и вернитесь сюда.",
    'g01-s04': "Оставьте Tor Browser открытым и нажмите «Проверить Tor».",
    'g02-s01': "Придумайте отдельный пароль и создайте кошелёк в хранилище с подтверждённым шифрованием.",
    'g02-s02': "Перепишите 25 слов по порядку на бумагу; не фотографируйте и не отправляйте их.",
    'g02-s03': "Перейдите к получению XMR, оставив хранилище открытым для показа адреса.",
    'g03-s01': "Откройте своё хранилище и подготовьте Feather; первый запуск будет без сети.",
    'g03-s02': "В Restore wallet from seed выберите 25-word Monero / legacy seed и введите 25 слов с этапа 2.",
    'g03-s03': "Сохраните файл Feather на зашифрованном носителе и задайте ему отдельный длинный пароль.",
    'g03-s04': "Дождитесь соединения Tor Browser, подключите Feather через Tor и дождитесь синхронизации.",
    'g03-s05': "Нажмите «Показать адрес моего кошелька», откройте Receive в Feather и сравните основной адрес целиком.",
    'g03-s06': "Выберите доступный вам способ получения XMR и прочитайте его условия до перевода.",
    'g03-s07': "Получите небольшую проверочную сумму и дождитесь её появления в доступном балансе Feather.",
    'g03-s08': "Для уже выбранной услуги получите новый счёт продавца именно в XMR.",
    'g03-s09': "Сверьте весь адрес и сумму в Feather; только затем подтверждайте перевод.",
    'g03-s10': "После перевода дождитесь статуса оплаты в своём заказе у продавца.",
    'g04-s01': "Решите, нужен ли дополнительный VPN; при выборе обычного Tor пропустите этот этап.",
    'g04-s02': "В Tor Browser откройте официальный Mullvad → Create account и сохраните номер своего аккаунта в менеджере паролей.",
    'g04-s03': "На официальном сайте откройте Add time → Monero.",
    'g04-s04': "Установите официальное приложение выбранного VPN и дождитесь подключения в нём.",
    'g04-s05': "Откройте Settings → VPN settings → Lockdown mode и выберите нужное поведение при отключении.",
    'g04-s06': "После подключения VPN откройте Tor Browser и заново проверьте Tor в мастере.",
    'g05-s01': "Подготовьте образ Tails и дождитесь сообщения о проверке.",
    'g05-s02': "Сверьте название и размер нужной флешки в списке перед её выбором.",
    'g05-s03': "Ещё раз проверьте выбранную флешку, подтвердите стирание и дождитесь результата записи.",
    'g06-s01': "Сверьте четыре требования к серверу перед выбором тарифа.",
    'g06-s02': "Перенесите шаблон в поддержку провайдера и дождитесь явного ответа перед оплатой.",
    'g06-s03': "Сравните актуальные условия на сайтах провайдеров перед заказом.",
    'g06-s04': "Откройте действующую форму регистрации и проверьте обязательные поля до покупки.",
    'g06-s05': "Прочитайте подсказку провайдера к полю Hostname и укажите допустимое имя сервера.",
    'g06-s06': "Проверьте окончательный заказ на сайте провайдера перед самостоятельной оплатой.",
    'g06-s07': "В панели провайдера установите Debian 13 amd64 на отдельный свежий сервер.",
    'g07-s01': "Выберите номер с понятным продлением, восстановлением и получением кодов.",
    'g07-s02': "Оформите подходящий номер сами и сохраните доступ к сервису и дату продления.",
    'g07-s03': "Выберите вход в существующий аккаунт или создание нового через официальный Telegram на телефоне.",
    'g08-s01': "Выполните команду ниже в консоли провайдера и сохраните SHA256-отпечаток своего сервера.",
    'g08-s02': "Введите адрес своего сервера, сверенный отпечаток и root-пароль в форму ниже.",
    'g08-s03': "Отметьте два условия сервера и нажмите «Начать настройку».",
    'g08-s04': "После успешного итога установки получите карточку доступа.",
    'g09-s01': "Откройте свой адрес из карточки в Tor Browser и войдите по данным карточки.",
    'g09-s02': "В кабинете выберите Gateway и дождитесь его сообщения о соединении с Tor.",
    'g09-s03': "Наблюдайте автоматическую подготовку Workstation в режиме обслуживания.",
    'g09-s04': "Дождитесь завершения установки Telegram и штатного выключения Workstation.",
    'g09-s05': "Дождитесь рабочего стола Workstation в обычной USER Session.",
    'g09-s06': "Нажмите «Проверить готовность сейчас» и прочитайте живой результат проверки.",
    'g10-s01': "Откройте карточку на этапе 9 и сохраните доступ отдельно от мастера.",
    'g10-s02': "Запустите проверку защитных настроек и прочитайте отчёт по каждому пункту.",
    'g10-s03': "Подготовьте памятку с onion-адресом для следующего устройства.",
    'g11-s01': "Сохраните доступ, откройте инструкцию на другом экране и подготовьтесь к выключению компьютера.",
    'g11-s02': "В меню загрузки стрелками выберите USB / EFI с названием своей флешки и нажмите Enter.",
    'g11-s03': "В Welcome to Tails выберите язык и раскладку, затем нажмите Start Tails.",
    'g11-s04': "В правом верхнем углу Tails выберите свою Wi-Fi сеть и введите пароль либо подключите Ethernet-кабель.",
    'g11-s05': "Откройте Tor Connection и выберите подходящий для своей сети способ подключения.",
    'g11-s06': "После подтверждения Tor откройте полный сохранённый onion-адрес в Tor Browser.",
    'g12-s01': "Выберите устройство, с которого входите сейчас, и выполняйте его подсказки по порядку.",
    'g12-s02': "Из своей карточки вставьте полный onion-адрес в Tor Browser; случайную ссылку из чата не используйте.",
    'g12-s03': "Введите имя, пароль кабинета и текущий шестизначный код своего аутентификатора.",
    'g12-s04': "Откройте Workstation → USER Session → Telegram.",
    'g12-s05': "Выйдите из кабинета, закройте браузер и отдельно закройте хранилище кошелька, если оно открыто.",
    'g13-s01': "Для этой Workstation нажмите «Проверить автоочистку».",
    'g13-s02': "Скачайте файл внутри Workstation и дождитесь роста счётчика готовых копий.",
    'g13-s03': "В «Файлы» → домашняя папка → OnionDesk-Clean откройте обработанную копию и проверьте, что она читается."
  });
  function makeMentor(text, id) {
    const box = document.createElement('aside');
    box.className = 'mentor-card';
    box.setAttribute('aria-label', 'Подсказка проводника');
    const avatar = document.createElement('img');
    avatar.src = '/assets/hacker-mark.png'; avatar.alt = ''; avatar.width = 56; avatar.height = 56;
    const copy = document.createElement('div');
    const name = document.createElement('span'); name.className = 'mentor-name'; name.textContent = 'Ваш проводник';
    const quote = document.createElement('p'); quote.id = id; quote.textContent = text;
    copy.append(name, quote); box.append(avatar, copy);
    return box;
  }
  function updateMarks() {
    document.querySelectorAll('[data-action-mark]').forEach((input) => {
      const done = markedActions.has(input.dataset.actionMark);
      input.checked = done;
      input.nextElementSibling.textContent = done ? 'Отмечено вами' : 'Я выполнил это действие';
      input.closest('.action-completion').classList.toggle('is-marked', done);
    });
    document.querySelectorAll('[data-page]').forEach((page) => {
      const cards = [...page.querySelectorAll('[data-inner-step]')];
      const count = cards.filter((card) => markedActions.has(card.dataset.artKey)).length;
      const button = document.querySelector(`[data-step="${page.dataset.page}"]`);
      const dailyCount = page.dataset.page === '12' ? markedDaily.size : 0;
      button.querySelector('small').textContent = `${count} из ${cards.length} отмечено вами${dailyCount ? ` · подсказки ${dailyCount}` : ''}`;
      button.classList.toggle('is-marked', count === cards.length);
      button.dataset.markedCount = String(count);
      button.dataset.totalCount = String(cards.length);
    });
  }
  function makeActionMark(key) {
    const box = document.createElement('div'); box.className = 'action-completion';
    const label = document.createElement('label');
    const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.actionMark = key;
    input.setAttribute('aria-describedby', `mark-help-${key}`);
    const text = document.createElement('span'); text.textContent = 'Я выполнил это действие';
    const help = document.createElement('p'); help.id = `mark-help-${key}`; help.className = 'field-help';
    help.textContent = 'Личная отметка на этот запуск. Проверки программы и результаты операций показаны отдельно.';
    if (key !== 'daily') input.addEventListener('change', () => {
      if (!closed && !(state && state.closing)) {
        if (input.checked) markedActions.add(key); else markedActions.delete(key);
      }
      updateMarks();
    });
    label.append(input, text); box.append(label, help); return box;
  }
  function setupGuidedPages() {
    document.querySelectorAll('[data-page]').forEach((page) => {
      const header = document.createElement('header'); header.className = 'stage-header';
      header.append(page.querySelector('.goal-art-frame'), page.querySelector('.page-heading'));
      const optional = page.querySelector('.optional-row');
      if (optional) { optional.classList.add('stage-option'); header.append(optional); }
      page.prepend(header);
      page.querySelector('.goal-outcome').hidden = true;
      page.querySelectorAll('[data-inner-step]').forEach((card) => {
        const key = card.dataset.artKey;
        card.querySelector(':scope > .card-index').hidden = true;
        const heading = card.querySelector(':scope > h2');
        heading.after(makeMentor(mentorTips[key], `mentor-${key}`));
        if (key === 'g00-s01') {
          const context = document.createElement('details'); context.className = 'action-context';
          const summary = document.createElement('summary'); summary.textContent = 'Как устроен маршрут';
          context.append(summary, card.querySelector('.three-grid'));
          card.querySelector('.expected-result').before(context);
        }
        card.querySelector('.expected-result > span').textContent = 'Ориентир результата';
        card.querySelector('.expected-result').after(makeActionMark(key));
        const leadControls = {
          'g01-s02': [$('launch-tor'), $('bundle-state')],
          'g01-s04': [$('check-tor'), $('tor-state')],
          'g03-s01': [$('feather-action'), $('feather-connect'), $('feather-version'), $('feather-state'), $('feather-network-help')],
          'g13-s01': [card.querySelector('.cleaner-actions'), $('auto-cleaner-state'), $('auto-cleaner-guidance')]
        }[key];
        if (leadControls) {
          let previous = card.querySelector(':scope > .mentor-card');
          leadControls.forEach((control) => { previous.after(control); previous = control; });
        }
      });
    });
    const daily = $('daily-guide');
    const title = $('daily-guide-title');
    title.after(makeMentor('', 'daily-mentor-quote'));
    const mark = makeActionMark('daily');
    mark.classList.add('daily-completion');
    const input = mark.querySelector('input'); input.removeAttribute('data-action-mark'); input.id = 'daily-complete';
    // The conditional guide has its own personal marks, separate from the five stage actions.
    input.addEventListener('change', () => {
      const key = dailyGuideKey(); const index = dailyPositions.get(key) || 0;
      if (!closed && !(state && state.closing) && dailyGuides[key]) {
        if (input.checked) markedDaily.add(`${key}:${index}`); else markedDaily.delete(`${key}:${index}`);
      }
      updateDailyMark(); updateMarks();
    });
    daily.querySelector('.device-guide-actions').before(mark);
    updateMarks();
  }
  function updateDailyMark() {
    const key = dailyGuideKey(); const index = dailyPositions.get(key) || 0;
    const input = $('daily-complete'); if (!input) return;
    const done = markedDaily.has(`${key}:${index}`);
    input.checked = done;
    input.nextElementSibling.textContent = done ? 'Отмечено вами' : 'Я выполнил этот шаг';
    input.setAttribute('aria-label', `${$('daily-guide-title').textContent} ${done ? 'Отмечено вами' : 'Я выполнил этот шаг'}`);
    input.closest('.action-completion').classList.toggle('is-marked', done);
  }

  function updateStepArt(page, index) {
    const cards = [...page.querySelectorAll('[data-inner-step]')];
    const card = cards[index];
    const key = card && card.dataset.artKey;
    if (!STEP_ART_KEYS.has(key)) return;
    const image = page.querySelector('[data-goal-image]');
    const frame = page.querySelector('.goal-art-frame');
    const source = `/assets/microsteps/${key}.png`;
    const title = card.querySelector('h2').textContent;
    image.alt = 'Художественная иллюстрация действия: ' + title;
    frame.setAttribute('aria-label', `Действие ${index + 1} из ${cards.length}. Иллюстрация: ${title}`);
    frame.querySelector('[data-art-step-label]').textContent = `ЭТАП ${page.dataset.page.padStart(2, '0')} / ДЕЙСТВИЕ ${index + 1}`;
    if (image.dataset.artKey === key && image.dataset.artState === 'ready') {
      if (Number(page.dataset.page) === activeStep) $('view-scene').disabled = closed || !image.complete || !image.naturalWidth;
      return;
    }
    if (Number(page.dataset.page) === activeStep) $('view-scene').disabled = true;
    image.dataset.artKey = key;
    image.dataset.artState = 'loading';
    image.onerror = () => {
      if (image.dataset.artKey !== key) return;
      image.onerror = null;
      image.dataset.artState = 'fallback';
      image.src = image.dataset.fallbackSrc;
    };
    image.onload = () => {
      if (image.dataset.artKey === key) {
        image.dataset.artState = image.getAttribute('src') === source ? 'ready' : 'fallback';
        if (Number(page.dataset.page) === activeStep) $('view-scene').disabled = closed;
      }
    };
    image.src = source;
  }
  function drawInner(page, index, focus = false) {
    const cards = [...page.querySelectorAll('[data-inner-step]')];
    if (!Number.isInteger(index) || index < 0 || index >= cards.length) return;
    const step = Number(page.dataset.page);
    const previous = innerPositions.get(step) || 0;
    if (previous !== index) {
      hideSecrets();
      // An unopened, newly created phrase stays pending until its explicit reveal.
      // Once shown, leaving its action invalidates both DOM words and challenge.
      const hadWords = !$('wallet-seed-panel').hidden;
      wipeWalletSecrets(hadWords);
    }
    innerPositions.set(step, index);
    cards.forEach((card, position) => { card.hidden = position !== index; });
    page.querySelector('[data-inner-position]').textContent = `ДЕЙСТВИЕ ${index + 1} ИЗ ${cards.length}`;
    const progress = page.querySelector('[data-inner-progress]');
    progress.max = cards.length; progress.value = index + 1;
    page.querySelector('[data-inner-back]').disabled = index === 0;
    page.querySelector('[data-inner-next]').textContent = index === cards.length - 1
      ? (step === 13 ? 'Вернуться к плану →' : 'К следующему этапу →') : 'Следующее действие →';
    updateStepArt(page, index);
    if (focus) {
      collapseWalletControls();
      showStepStart(page);
    }
  }

  setupGuidedPages();
  document.querySelectorAll('[data-step]').forEach((button) => button.addEventListener('click', () => go(Number(button.dataset.step))));
  document.querySelectorAll('[data-go]').forEach((button) => button.addEventListener('click', () => go(Number(button.dataset.go))));
  document.querySelectorAll('[data-action-go]').forEach((button) => button.addEventListener('click', () => {
    if (closed) return;
    const step = Number(button.dataset.actionGo);
    const index = Number(button.dataset.actionIndex);
    if (!Number.isInteger(step) || step < 0 || step >= SCENES.length) return;
    const page = document.querySelector(`[data-page="${step}"]`);
    const heading = page.querySelector(`[data-inner-step="${index}"] > h2`);
    if (!heading) return;
    if (activeStep !== step) go(step);
    drawInner(page, index, true);
    if (button.closest('#wallet-corner')) collapseWalletControls();
  }));
  document.querySelectorAll('[data-page]').forEach((page) => {
    const step = Number(page.dataset.page);
    page.querySelector('[data-inner-back]').addEventListener('click', () => {
      if (!closed) drawInner(page, (innerPositions.get(step) || 0) - 1, true);
    });
    page.querySelector('[data-inner-next]').addEventListener('click', () => {
      if (closed) return;
      const next = (innerPositions.get(step) || 0) + 1;
      if (next < page.querySelectorAll('[data-inner-step]').length) drawInner(page, next, true);
      else go(step === 13 ? 0 : step + 1);
    });
    page.querySelectorAll('[data-inner-jump]').forEach((button) => button.addEventListener('click', () => {
      if (!closed) drawInner(page, Number(button.dataset.innerJump), true);
    }));
    drawInner(page, 0);
  });
  // Arrow keys also move the horizontal mobile navigation into view.
  $('steps').addEventListener('keydown', (event) => {
    const current = event.target.closest('[data-step]');
    if (!current || !['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const step = Number(current.dataset.step);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? 13
      : Math.max(0, Math.min(13, step + (event.key === 'ArrowRight' ? 1 : -1)));
    go(next);
    document.querySelector(`[data-step="${next}"]`).focus({preventScroll: true});
  });
  function revealNavButton(button) {
    const nav = $('steps');
    if (!button || !nav.clientWidth || !nav.clientHeight) return;
    const frame = nav.getBoundingClientRect();
    const item = button.getBoundingClientRect();
    const left = frame.left + nav.clientLeft;
    const top = frame.top + nav.clientTop;
    const dx = item.left < left ? item.left - left : Math.max(0, item.right - left - nav.clientWidth);
    const dy = item.top < top ? item.top - top : Math.max(0, item.bottom - top - nav.clientHeight);
    if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) nav.scrollBy({left: dx, top: dy, behavior: 'instant'});
  }
  $('steps').addEventListener('focusin', (event) => revealNavButton(event.target.closest('[data-step]')));
  let navRevealFrame = 0;
  function scheduleNavReveal() {
    if (closed || navRevealFrame) return;
    navRevealFrame = requestAnimationFrame(() => {
      navRevealFrame = 0;
      if (closed) return;
      // Adjust only this menu; revealing the row must not scroll the instructions.
      revealNavButton($('steps').querySelector('[aria-current="step"]'));
    });
  }
  window.addEventListener('resize', scheduleNavReveal);
  document.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', () => copy(button.dataset.copy)));
  document.querySelectorAll('[data-copy-from]').forEach((button) => button.addEventListener('click', () => copy($(button.dataset.copyFrom).textContent)));
  document.querySelectorAll('[data-toggle]').forEach((button) => button.addEventListener('click', () => toggleSecret($(button.dataset.toggle), button)));
  const bootKeys = {
    dell:'При включении несколько раз нажмите F12, пока не появится меню загрузки.',
    lenovo:'При появлении логотипа Lenovo несколько раз нажмите F12; на части моделей — Fn+F12.',
    hp:'Сразу при включении несколько раз нажмите Esc. В Startup Menu нажмите F9 — Boot Device Options.',
    asus:'На многих ноутбуках ASUS удерживайте Esc, одновременно нажмите питание и отпустите Esc после появления Boot Menu. Другие модели могут использовать иной путь.',
    mac:'Только Mac с Intel: сразу после включения удерживайте Option (⌥ / Alt), затем выберите флешку в Startup Manager. Совместимость Tails зависит от модели.',
    other:'Найдите в инструкции вашей модели пункт Boot Menu / выбор загрузочного устройства. Не угадывайте настройки BIOS. Приложение не может открыть это меню автоматически.'
  };
  $('computer-brand').addEventListener('change', () => {
    const key = $('computer-brand').value;
    $('boot-key').textContent = Object.prototype.hasOwnProperty.call(bootKeys, key) ? bootKeys[key]
      : 'Выберите известную марку или пункт «Другой компьютер». Подсказка для неизвестного выбора недоступна.';
  });
  $('check-tor').addEventListener('click', () => perform('/api/tor/check'));
  $('download-tails').addEventListener('click', () => perform('/api/usb/download'));
  $('launch-tor').addEventListener('click', () => perform('/api/tor/start'));
  $('feather-action').addEventListener('click', () => {
    if (closed || !state || state.closing || submittingJob || phoneRequestPending || autoCleanerRequest
        || (state.job && state.job.state === 'running')) return;
    const feather = state.feather || {};
    if (feather.available !== true || feather.running === true) return;
    if (feather.workspace_open !== true) { walletShortcut(2, 0, 'open'); return; }
    perform(feather.prepared === true ? '/api/feather/launch' : '/api/feather/prepare');
  });
  $('feather-stop').addEventListener('click', () => {
    const feather = state && state.feather || {};
    if (feather.running === true || (feather.prepared === true && feather.workspace_open === true)) perform('/api/feather/stop');
  });
  $('feather-connect').addEventListener('click', () => {
    if (closed || !state || state.closing || submittingJob || phoneRequestPending || autoCleanerRequest
        || (state.job && state.job.state === 'running')) return;
    const feather = state.feather || {};
    if (feather.available === true && feather.prepared === true && feather.workspace_open === true && feather.running !== true) perform('/api/feather/connect');
  });
  $('refresh-disks').addEventListener('click', disks);
  $('usb-disk').addEventListener('change', () => { $('erase-confirmation').value = ''; });
  $('write-usb').addEventListener('click', () => {
    const selection = $('usb-disk').value; const confirmation = $('erase-confirmation').value;
    if (!selection) return showError('Сначала выберите флешку из обновлённого списка.');
    if (confirmation !== 'СТЕРЕТЬ') return showError('Введите ровно СТЕРЕТЬ. Все данные выбранной флешки будут удалены.');
    $('erase-confirmation').value = '';
    perform('/api/usb/write', {selection, confirmation});
  });
  $('connect-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const data = {host:$('server-host').value.trim(), password:$('root-password').value, fingerprint:$('ssh-fingerprint').value.trim()};
    $('root-password').value = ''; $('root-password').type = 'password';
    const toggle = document.querySelector('[data-toggle="root-password"]'); toggle.textContent = 'Показать'; toggle.setAttribute('aria-pressed','false');
    perform('/api/server/connect', data).finally(() => { data.password = ''; });
  });
  $('install-server').addEventListener('click', () => {
    if (!state || !state.server_connected) return showError('Сначала заполните три поля и подключитесь к серверу.');
    if (!$('fresh-server').checked || !$('accept-licenses').checked) return showError('Подтвердите отдельный свежий сервер и условия Whonix перед настройкой.');
    perform('/api/server/install', {fresh_server:true, licenses:true});
  });
  $('resume-install').addEventListener('click', () => {
    if (!state || !state.server_connected) return showError('Сначала подключитесь к тому же серверу тремя полями выше.');
    perform('/api/server/resume');
  });
  $('recover-card').addEventListener('click', () => perform('/api/server/credentials'));
  $('start-workstation').addEventListener('click', () => perform('/api/server/action', {action:'start'}));
  $('check-ready').addEventListener('click', () => perform('/api/server/action', {action:'status'}));
  $('audit-server').addEventListener('click', () => {
    if (!state || !state.server_connected) return showError('Для проверки подключитесь к своему серверу на этапе 8.');
    perform('/api/server/action', {action:'audit'});
  });
  $('prepare-handoff').addEventListener('click', prepareHandoff);
  $('copy-handoff').addEventListener('click', () => {
    if ($('handoff-note').value) copy($('handoff-note').value);
  });
  $('cancel-job').addEventListener('click', () => perform('/api/job/cancel'));
  $('show-card').addEventListener('click', showCard);
  $('hide-card').addEventListener('click', hideSecrets);
  $('clear-card').addEventListener('click', async () => {
    hideSecrets();
    if (closed) return;
    try {
      await api('/api/secrets/clear', {});
      if (!closed) toast('Карточка удалена из памяти мастера. При необходимости получите её с сервера снова.');
    } catch (error) { if (!closed) showError(error.message); }
  });
  $('wallet-create-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submitWalletPassword('/api/wallet/create', ['wallet-password', 'wallet-password-confirm']);
  });
  $('wallet-unlock-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!$('wallet-vault').value) return showError('Выберите своё хранилище из списка.');
    submitWalletPassword('/api/wallet/unlock', ['wallet-unlock-password'], {vault_id: $('wallet-vault').value});
  });
  $('wallet-reveal-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!$('wallet-select').value) return showError('Сначала загрузите и выберите свой кошелёк.');
    submitWalletPassword('/api/wallet/reveal', ['wallet-reveal-password'], {wallet_id: $('wallet-select').value});
  });
  $('wallet-vault').addEventListener('change', () => { if (state) renderWallet(Boolean(state.job && state.job.state === 'running')); });
  $('wallet-select').addEventListener('change', () => { if (state) renderWallet(Boolean(state.job && state.job.state === 'running')); });
  $('wallet-load').addEventListener('click', () => loadWallets());
  $('wallet-receive-list').addEventListener('click', () => loadWallets(true));
  $('wallet-receive-select').addEventListener('change', updateWalletAddress);
  $('wallet-copy-address').addEventListener('click', () => {
    if (activeStep === 3 && !$('wallet-receive-panel').hidden && $('wallet-address').value) copy($('wallet-address').value);
  });
  $('wallet-seed').addEventListener('click', showWalletSeed);
  $('wallet-hide-seed').addEventListener('click', () => {
    wipeWalletSecrets();
    $('wallet-backup-state').textContent = 'Слова скрыты. Для повторного просмотра снова введите пароль.';
  });
  $('wallet-backup-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!walletChallenge || $('wallet-seed-panel').hidden) return showError('Сначала подготовьте и покажите фразу восстановления.');
    const answers = [0, 1, 2].map((index) => $('wallet-answer-' + index).value.trim().toLowerCase());
    if (!answers.every((word) => /^[a-z]{1,32}$/.test(word))) return showError('Введите три английских слова из своей бумажной записи.');
    const data = {...walletChallenge, answers};
    const operation = perform('/api/wallet/confirm', data);
    wipeWalletSecrets(false);
    answers.fill('');
    operation.then((accepted) => { if (accepted) $('wallet-backup-state').textContent = state && state.job && state.job.kind === 'wallet-confirm' && state.job.state === 'done'
      ? '✓ Резервная копия подтверждена. Полную бумажную фразу храните отдельно.' : 'Слова скрыты. Дождитесь результата проверки в ходе операции.'; });
  });
  $('wallet-lock').addEventListener('click', lockWallet);
  $('wallet-corner-open').addEventListener('click', () => walletShortcut(2, 0, 'open'));
  $('wallet-corner-words').addEventListener('click', () => walletShortcut(2, 1, 'words'));
  $('wallet-corner-receive').addEventListener('click', () => walletShortcut(3, 4, 'receive'));
  $('wallet-corner-lock').addEventListener('click', lockWallet);
  $('quit').addEventListener('click', async () => {
    if (closed || submittingJob || (state && (state.closing || (state.job && state.job.state === 'running')))) return;
    submittingJob = true;
    try {
      $('root-password').value = '';
      if (state) render(state);
      clearError(); hideSecrets(); wipeWalletSecrets();
      await api('/api/quit', {}); closed = true; nonce = '';
      document.querySelectorAll('button').forEach((button) => { button.disabled = true; });
      $('root-password').value = ''; toast('Приложение завершено. Эту страницу можно закрыть.');
    } catch (error) { if (!closed) showError(error.message); }
    finally {
      submittingJob = false;
      if (state && !closed) render(state);
    }
  });
  window.addEventListener('pagehide', () => { hideSecrets(); wipeWalletSecrets(); $('root-password').value = ''; nonce = ''; });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { hideSecrets(); wipeWalletSecrets(); $('root-password').value = ''; }
  });
  $('connection-choice').addEventListener('change', () => {
    if (closed) return;
    const advice = {
      tor: 'Мосты помогают подключиться при блокировках. В копии Tor Browser из комплекта они уже включены.',
      vpn: 'Дополнительный маршрут VPN → Tor настраивается на этапе 4.',
      tails: 'Вход с готовой флешки Tails и её встроенный Tor Connection разобраны на этапе 11. Внутри Tails VPN не устанавливайте.'
    };
    const key = $('connection-choice').value;
    $('connection-advice').textContent = Object.prototype.hasOwnProperty.call(advice, key) ? advice[key]
      : 'Выберите известный маршрут из списка. Для неизвестного выбора инструкция недоступна.';
  });
  $('daily-device').addEventListener('change', () => { if (!closed) drawDailyGuide(true); });
  $('daily-method').addEventListener('change', () => { if (!closed) drawDailyGuide(true); });
  function moveDailyGuide(direction) {
    if (closed) return;
    const key = dailyGuideKey();
    const guide = dailyGuides[key];
    if (!guide) return;
    const next = (dailyPositions.get(key) || 0) + direction;
    if (next < 0 || next >= guide.steps.length) return;
    dailyPositions.set(key, next);
    drawDailyGuide(true);
  }
  $('daily-guide-back').addEventListener('click', () => moveDailyGuide(-1));
  $('daily-guide-next').addEventListener('click', () => moveDailyGuide(1));
  $('auto-cleaner-check').addEventListener('click', requestAutoCleaner);
  $('phone-device').addEventListener('change', () => renderPhone(Boolean(state && state.job && state.job.state === 'running')));
  $('phone-list').addEventListener('click', () => {
    if (dailyUsbAction(3) && state && state.phone && state.phone.available === true) performPhone('/api/phone/list');
  });
  $('phone-install').addEventListener('click', () => {
    if (!dailyUsbAction(5) || !state || !state.phone || state.phone.available !== true) return;
    if (state.phone.session_open !== true) return showError('Сначала найдите телефон кнопкой поиска и подтвердите USB-разрешение.');
    const devices = Array.isArray(state.phone.devices) ? state.phone.devices : [];
    const device = devices.find((item) => item && typeof item.id === 'string' && item.id.length > 0
      && item.id.length <= 256 && item.id === $('phone-device').value && item.state === 'device');
    if (!device) return showError('Сначала выберите свой Android с подтверждённым USB-разрешением.');
    performPhone('/api/phone/install', {device_id: device.id});
  });
  function closePhoneSession() {
    if (state && state.phone && (state.phone.session_open || state.phone.cleanup_required)) performPhone('/api/phone/close');
  }
  $('phone-close').addEventListener('click', closePhoneSession);
  $('phone-close-guide').addEventListener('click', () => { if (dailyUsbAction(7)) closePhoneSession(); });
  drawDailyGuide();
  let walletControlsExpanded = false;
  function updateWalletControls() {
    $('wallet-corner-toggle').setAttribute('aria-expanded', String(walletControlsExpanded));
    $('wallet-corner-controls').hidden = !walletControlsExpanded;
  }
  function collapseWalletControls() {
    walletControlsExpanded = false;
    updateWalletControls();
  }
  $('wallet-corner-toggle').addEventListener('click', () => {
    if (closed) return;
    walletControlsExpanded = !walletControlsExpanded;
    updateWalletControls();
  });
  $('wallet-corner').addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !walletControlsExpanded) return;
    event.preventDefault();
    event.stopPropagation();
    collapseWalletControls();
    $('wallet-corner-toggle').focus({preventScroll: true});
  });
  updateWalletControls();
  const sidebar = document.querySelector('.sidebar');
  const updateSidebarHeight = () => document.documentElement.style.setProperty('--sidebar-height', `${Math.ceil(sidebar.getBoundingClientRect().height)}px`);
  updateSidebarHeight();
  if (typeof ResizeObserver === 'function') {
    const navLayoutObserver = new ResizeObserver(() => { updateSidebarHeight(); scheduleNavReveal(); });
    [sidebar, $('steps'), ...document.querySelectorAll('#steps .nav-group')].forEach((element) => navLayoutObserver.observe(element));
  }
  else window.addEventListener('resize', updateSidebarHeight);
  if (!nonce) showError('Откройте приложение через его значок. Эта страница не получила код текущего запуска.');
  else { poll(); loadGuideShots(); setInterval(poll, 1800); }
})();
