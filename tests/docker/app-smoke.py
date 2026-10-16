"""Browser regression for the local wizard without USB writes or external actions."""
import io
import json
import math
from pathlib import Path
import sys
import threading

ROOT = Path('/workspace/outputs/remote-desktop-kit')
LOG = Path('/logs')
sys.path.insert(0, str(ROOT / 'client'))
sys.path.insert(0, str(ROOT / 'tests/docker/unit'))
import app
from test_app import FakeEngine, FakeUSB, FakeRemote, FakeWallet, FakeOffline
from playwright.sync_api import sync_playwright
from PIL import Image


capture_checks = []


def navigate(page, step, action=0):
    page.locator(f'[data-step="{step}"]').click()
    current = page.locator(f'[data-page="{step}"]')
    current.wait_for(state='visible')
    while int(current.locator('[data-inner-step]:visible').get_attribute('data-inner-step')) > action:
        current.locator('[data-inner-back]').click()
    while int(current.locator('[data-inner-step]:visible').get_attribute('data-inner-step')) < action:
        current.locator('[data-inner-next]').click()
    return current


def capture_action(page, current, destination=None, *, full_page=True):
    # Lazy screenshots need the same visibility a person gives them by scrolling.
    # Restore the top before a full-page capture so sticky art is not stitched
    # behind the opaque reading surface at the previous scroll position.
    page.evaluate('() => document.fonts.ready')
    page.wait_for_function('''() => {
        const current=document.querySelector('[data-page]:not([hidden])');
        const image=current.querySelector('[data-goal-image]');
        const card=current.querySelector('[data-inner-step]:not([hidden])');
        return image.dataset.artState==='ready' && image.dataset.artKey===card.dataset.artKey
            && image.complete && image.naturalWidth>0;
    }''')
    current.locator('[data-goal-image]').evaluate('(el) => el.decode()')
    visible_images = [current.locator('[data-goal-image]')]
    for picture in current.locator('.guide-shot img').all():
        if picture.is_visible():
            visible_images.append(picture)
            picture.evaluate("el => el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'})")
            picture.evaluate('(el) => el.decode()')
            assert picture.evaluate('(el) => el.complete && el.naturalWidth > 0')
    page.evaluate('''() => {
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
        window.scrollTo({top:0,left:0,behavior:'instant'});
    }''')
    # A decoded image can still be invisible during the page's arrival animation.
    # Wait for real animation completion and stable browser scroll positions;
    # screenshot animation overrides alone do not settle sticky compositing.
    page.evaluate('''async () => {
        const finite=document.getAnimations().filter(animation =>
            Number.isFinite(animation.effect.getComputedTiming().endTime));
        await Promise.all(finite.map(animation => animation.finished.catch(() => {})));
        let stable=0, previous='';
        const deadline=performance.now()+5000;
        while (stable<8) {
            if(performance.now()>deadline) throw new Error('Capture scroll positions did not settle');
            await new Promise(requestAnimationFrame);
            const active=document.querySelector('[data-step][aria-current="step"]');
            const rect=active.getBoundingClientRect();
            const positions=[scrollX,scrollY,
                ...[...document.querySelectorAll('.sidebar, #steps')].flatMap(el => [el.scrollLeft,el.scrollTop]),
                rect.left,rect.top,rect.right,rect.bottom].map(value => Math.round(value*10)/10).join(',');
            stable=positions===previous ? stable+1 : 0;
            previous=positions;
        }
        await new Promise(requestAnimationFrame);
        await new Promise(requestAnimationFrame);
    }''')
    # Use the same visibility decision as the decode loop. A closed <details>
    # may expose descendant client rects without painting its lazy images.
    image_handles = [image.element_handle() for image in visible_images]
    page.wait_for_function('''images => {
        return scrollY===0 && images.every(image => {
            for(let el=image;el;el=el.parentElement) {
                if(Number(getComputedStyle(el).opacity)<.999) return false;
            }
            return image.complete && image.naturalWidth>0;
        });
    }''', arg=image_handles)
    checks = page.evaluate('''guideImages => {
        const active=document.querySelector('[data-step][aria-current="step"]');
        const nav=document.querySelector('#steps').getBoundingClientRect();
        const sidebar=document.querySelector('.sidebar').getBoundingClientRect();
        const rect=active.getBoundingClientRect();
        const current=document.querySelector('[data-page]:not([hidden])');
        return {width:innerWidth,step:Number(current.dataset.page),
            key:current.querySelector('[data-inner-step]:not([hidden])').dataset.artKey,
            scroll_y:scrollY,nav_left:rect.left,nav_right:rect.right,
            nav_visible_left:Math.max(0,nav.left,sidebar.left),
            nav_visible_right:Math.min(innerWidth,nav.right,sidebar.right),
            nav_height:rect.height,wallet_height:document.querySelector('#wallet-corner').getBoundingClientRect().height,
            guide_images:guideImages};
    }''', arg=len(visible_images)-1)
    assert checks['nav_left'] >= checks['nav_visible_left']-1 and checks['nav_right'] <= checks['nav_visible_right']+1, f'Current navigation card clipped after settling: {checks}'
    capture_checks.append({'file': Path(destination).name if destination else None, **checks})
    return page.screenshot(path=str(destination) if destination else None, full_page=full_page, animations='disabled')


def capture_region(page, current, region, destination):
    # Crop a settled full-page bitmap offline. Element screenshots scroll the
    # target under the sticky mobile header and can capture it over the content.
    bitmap = capture_action(page, current)
    rect = region.bounding_box()
    assert rect is not None and rect['width'] > 0 and rect['height'] > 0
    with Image.open(io.BytesIO(bitmap)) as image:
        image.crop((math.floor(rect['x']), math.floor(rect['y']),
                    math.ceil(rect['x']+rect['width']), math.ceil(rect['y']+rect['height']))).save(destination)


def main():
    usb = FakeUSB()
    wallets = FakeWallet()
    desk = app.Desk(usb=usb, engine=FakeEngine(), offline=FakeOffline(), wallets=wallets)
    server = app.LocalServer(desk)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    console_errors = []
    bad_responses = []
    external_requests = []
    measurements = []
    art_keys = set()
    clear_regression = {}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', args=['--no-sandbox'])
            for name, width, height in [('desktop', 1280, 900), ('wide', 1536, 1000), ('tablet', 768, 1024), ('mobile', 390, 844)]:
                context = browser.new_context(viewport={'width': width, 'height': height}, reduced_motion='reduce')
                page = context.new_page()
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.on('console', lambda message: console_errors.append(message.text) if message.type == 'error' else None)
                page.on('response', lambda response: bad_responses.append({'status': response.status, 'path': response.url.removeprefix(server.origin)}) if response.status >= 400 else None)
                page.on('request', lambda request: external_requests.append(request.url) if not request.url.startswith(server.origin + '/') else None)
                wallet_reads = []
                page.on('request', lambda request: wallet_reads.append(request.url) if request.url.endswith('/api/wallet/list') else None)
                page.goto(server.origin + '/#' + desk.nonce)
                page.wait_for_function("() => document.body.dataset.guideShotsState === 'ready'")
                page.wait_for_function("() => document.getElementById('device-name').textContent.includes('macOS')")
                page.evaluate('() => document.fonts.ready')
                assert page.evaluate('''() => [400, 700].every(weight =>
                    document.fonts.check(`${weight} 18px "OnionDesk Mono"`, 'Агент Ёж 0123456789') &&
                    [...document.fonts].some(font => font.family.includes('OnionDesk Mono') && font.weight === String(weight) && font.status === 'loaded'))'''), 'The actual bundled Cyrillic fonts must load'
                assert 'OnionDesk Mono' in page.locator('h1').first.evaluate('(el) => getComputedStyle(el).fontFamily')
                assert page.url == server.origin + '/'
                for step in range(14):
                    page.locator(f'[data-step="{step}"]').click()
                    page.locator(f'[data-page="{step}"]').wait_for(state='visible')
                    assert page.locator('[data-page]:visible').count() == 1
                    assert page.locator(f'[data-step="{step}"]').get_attribute('aria-current') == 'step'
                    overflow = page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')
                    assert overflow <= 1, f'{name} screen {step} horizontal overflow {overflow}'
                    grid = page.evaluate('''() => {
                        const current = document.querySelector('[data-page]:not([hidden])');
                        const rect = el => { const r=el.getBoundingClientRect(); return {left:r.left,width:r.width}; };
                        return {header:rect(document.querySelector('.topbar')),sheet:rect(current.querySelector('.mission-sheet')),
                                heading:stepHeading(current),scene:document.body.dataset.scene,
                                art:rect(current.querySelector('.goal-art-frame')),
                                overlap:current.querySelector('.goal-art-frame').getBoundingClientRect().bottom-current.querySelector('.mission-sheet').getBoundingClientRect().top,
                                hero_height:current.querySelector('.goal-art-frame').getBoundingClientRect().height};
                        function stepHeading(el) { const heading=el.querySelector('.page-heading'); return heading?rect(heading):null; }
                    }''')
                    assert abs(grid['header']['left']-grid['sheet']['left'])<=1, f'{name} {step}: left grid axis'
                    assert abs(grid['header']['width']-grid['sheet']['width'])<=1, f'{name} {step}: sheet width'
                    if grid['heading']:
                        assert grid['heading']['left'] > grid['sheet']['left'], f'{name} {step}: heading must sit inside the text panel'
                    assert grid['scene']==str(step)
                    assert abs(grid['header']['left']-grid['art']['left'])<=1
                    assert abs(grid['header']['width']-grid['art']['width'])<=1
                    assert abs(grid['overlap']-(56 if width<=650 else 72))<=1
                    assert .60 <= grid['hero_height']/height <= .70
                    page.wait_for_function('''step => {
                        const image=document.querySelector(`[data-page="${step}"] [data-goal-image]`);
                        return image.dataset.artState==='ready' && image.complete && image.naturalWidth>0;
                    }''', arg=step)
                    screenshot = LOG / f'app-{name}-{step}.png'
                    current = page.locator(f'[data-page="{step}"]')
                    capture_action(page, current, screenshot)
                    if name == 'desktop' and step in (0, 5, 8):
                        capture_action(page, current, LOG / f'app-font-guide-{dict([(0,0),(5,2),(8,4)])[step]}.png', full_page=False)
                    measurements.append({'viewport': name, 'step': step, 'horizontal_overflow': overflow, 'grid':grid})
                    current = page.locator(f'[data-page="{step}"]')
                    action_count = current.locator('[data-inner-step]').count()
                    for action in range(action_count):
                        visible = current.locator('[data-inner-step]:visible')
                        assert visible.count() == 1 and visible.get_attribute('data-inner-step') == str(action)
                        assert visible.locator('.expected-result').count() == 1
                        assert visible.locator(':scope > .action-help').count() == 1
                        key=visible.get_attribute('data-art-key')
                        if key == 'g06-s01':
                            requirements = visible.locator('.check-grid > *').all_text_contents()
                            assert len(requirements) == 4 and all(len(value.strip()) > 35 for value in requirements), 'Four empty boxes are not server requirements'
                        page.wait_for_function('''([step,key]) => {
                            const image=document.querySelector(`[data-page="${step}"] [data-goal-image]`);
                            return image.dataset.artState==='ready' && image.dataset.artKey===key && image.complete && image.naturalWidth>0;
                        }''', arg=[step,key])
                        assert current.locator('[data-goal-image]').get_attribute('src') == f'/assets/microsteps/{key}.png'
                        art_keys.add(key)
                        if name == 'desktop':
                            capture_action(page, current, LOG / f'action-{key}.png')
                        visible.locator(':scope > .action-help > summary').click()
                        assert visible.locator(':scope > .action-help').get_attribute('open') is not None
                        visible.locator(':scope > .action-help > summary').click()
                        if key == 'g12-s01':
                            assert visible.locator('#daily-usb-help').is_hidden()
                            page.locator('#daily-device').select_option('android')
                            assert visible.locator('#daily-usb-help').is_visible()
                            page.locator('#daily-method').select_option('phone')
                            assert visible.locator('#daily-usb-help').is_hidden()
                            page.locator('#daily-device').select_option('iphone')
                            assert visible.locator('#daily-usb-help').is_hidden()
                            page.locator('#daily-device').select_option('')
                        assert page.evaluate('() => document.documentElement.scrollWidth - innerWidth') <= 1
                        if step == 11:
                            capture_region(page, current, current.locator('.goal-guide'), LOG / f'app-{name}-tails-{action}.png')
                            if action == 1:
                                for brand in ('dell', 'lenovo', 'hp', 'asus', 'mac', 'other'):
                                    page.locator('#computer-brand').select_option(brand)
                                    assert len(page.locator('#boot-key').inner_text()) > 40
                        if action < action_count - 1:
                            current.locator('[data-inner-next]').focus()
                            page.keyboard.press('Enter')
                            assert current.locator('[data-inner-step]:visible > h2').evaluate('(el) => document.activeElement === el'), 'Next must focus the instruction, without another scroll past the illustration'
                    print(f'PASS {name} goal {step}: {action_count} actions, keyboard, help, no horizontal overflow', flush=True)
                assert page.locator('[data-step]').count() == 14
                assert page.locator('.nav-group').count() == 3
                assert wallet_reads == [], 'Navigation or polling exposed wallet details'
                assert page.evaluate('() => localStorage.length') == 0
                navigate(page, 6)
                page.locator('#view-scene').click()
                page.locator('#guide-shot-viewer').wait_for(state='visible')
                assert '/assets/microsteps/g06-s01.png' in page.locator('#guide-shot-viewer-image').get_attribute('src')
                page.keyboard.press('Escape')
                assert page.locator('#view-scene').evaluate('(el) => document.activeElement === el')
                page.locator('[data-step="6"]').focus()
                assert page.locator('[data-step="6"]').evaluate('(el) => document.activeElement === el'), 'End must start from an actually focused navigation card'
                page.keyboard.press('End')
                page.wait_for_function("() => document.querySelector('[data-step=\"13\"]').getAttribute('aria-current') === 'step'")
                assert page.locator('[data-step="13"]').get_attribute('aria-current') == 'step'
                assert 0 <= page.locator('[data-step="13"]').bounding_box()['x'] < width
                page.locator('[data-step="13"]').focus()
                assert page.locator('[data-step="13"]').evaluate('(el) => document.activeElement === el'), 'Home must start from an actually focused navigation card'
                page.keyboard.press('Home')
                page.wait_for_function("() => document.querySelector('[data-step=\"0\"]').getAttribute('aria-current') === 'step'")
                assert page.locator('[data-step="0"]').get_attribute('aria-current') == 'step'
                context.close()


            # All wallet data here is synthetic; no screenshot contains words.
            wallet_context = browser.new_context(viewport={'width':1280,'height':900}, reduced_motion='reduce')
            wallet_page = wallet_context.new_page()
            wallet_page.on('pageerror', lambda error: errors.append(str(error)))
            wallet_page.on('console', lambda message: console_errors.append(message.text) if message.type == 'error' else None)
            wallet_reads = []
            wallet_page.on('request', lambda request: wallet_reads.append(request.url) if request.url.endswith('/api/wallet/list') else None)
            wallet_page.goto(server.origin + '/#' + desk.nonce)
            navigate(wallet_page, 11, 2)
            wallet_page.locator('[data-guide-shot="tails-welcome"] .guide-shot-zoom').click()
            assert '/screens/real/' in wallet_page.locator('#guide-shot-viewer-image').get_attribute('src')
            wallet_page.keyboard.press('Escape')
            assert wallet_page.locator('[data-guide-shot="tails-welcome"] .guide-shot-zoom').evaluate('(el) => document.activeElement === el')
            navigate(wallet_page, 2)
            wallet_page.locator('#wallet-password').fill('synthetic-password-only')
            wallet_page.locator('#wallet-password-confirm').fill('synthetic-password-only')
            wallet_page.locator('#wallet-create').click()
            assert wallet_page.locator('#wallet-password').input_value() == ''
            assert wallet_page.locator('#wallet-password-confirm').input_value() == ''
            wallet_page.wait_for_function("() => document.querySelector('#job-kind').textContent === 'СОЗДАНИЕ КОШЕЛЬКА' && document.querySelector('#job-progress').value === 100")
            assert wallets.creations == 1 and wallet_page.locator('#wallet-words li').count() == 0
            wallet_page.wait_for_function("() => document.querySelector('#wallet-corner').dataset.state === 'unconfirmed'")
            assert wallet_reads == [], 'Creating or displaying the corner card must not retrieve addresses'
            assert wallet_page.locator('#operation-panel').evaluate("el => !['fixed','sticky'].includes(getComputedStyle(el).position) && el.getBoundingClientRect().bottom <= document.querySelector('#main').getBoundingClientRect().top + 1"), 'Operation feedback covers the instructions'
            capture_action(wallet_page, wallet_page.locator('[data-page="2"]'), LOG / 'wallet-created-card.png')
            capture_region(wallet_page, wallet_page.locator('[data-page="2"]'), wallet_page.locator('#wallet-corner'), LOG / 'wallet-created-widget.png')
            forgets = wallets.forgets
            wallet_page.locator('[data-step="2"]').click()
            wallet_page.wait_for_timeout(100)
            assert wallets.pending and wallets.forgets == forgets, 'Selecting the current goal lost the unshown recovery phrase'
            # Move within this goal without resetting its newly pending phrase.
            assert wallet_page.locator('#wallet-corner-toggle').get_attribute('aria-expanded') == 'false'
            wallet_page.locator('#wallet-corner-toggle').click()
            assert wallet_page.locator('#wallet-corner-toggle').get_attribute('aria-expanded') == 'true'
            wallet_page.locator('#wallet-corner-words').click()
            wallet_page.wait_for_function("() => !document.querySelector('#wallet-seed').disabled")
            wallet_page.locator('#wallet-seed').click()
            wallet_page.locator('#wallet-seed-panel').wait_for(state='visible')
            assert wallet_page.locator('#wallet-words li').count() == 25
            assert wallet_page.locator('#wallet-seed-panel [data-copy]').count() == 0
            for width in (1536,1280,768,390):
                wallet_page.set_viewport_size({'width':width,'height':900})
                assert wallet_page.evaluate('() => document.documentElement.scrollWidth - innerWidth') <= 1
            for index in range(3): wallet_page.locator(f'#wallet-answer-{index}').fill('demo')
            wallet_page.locator('#wallet-confirm-backup').click()
            wallet_page.locator('#wallet-backup-state').filter(has_text='Резервная копия подтверждена').wait_for()
            assert wallets.record['backup_confirmed'] and wallet_page.locator('#wallet-words li').count() == 0
            wallet_page.wait_for_function("() => document.querySelector('#wallet-corner').dataset.state === 'confirmed'")
            assert 'demo' not in wallet_page.locator('#wallet-corner').inner_text()
            assert wallets.record['address'] not in wallet_page.locator('#wallet-corner').inner_text()
            for width in (1536,1280,768,390):
                wallet_page.set_viewport_size({'width':width,'height':900})
                assert wallet_page.locator('#wallet-corner').is_visible()
                assert wallet_page.evaluate('() => document.documentElement.scrollWidth - innerWidth') <= 1
                capture_action(wallet_page, wallet_page.locator('[data-page="2"]'), LOG / f'wallet-confirmed-{width}.png')
            navigate(wallet_page, 3, 4)
            before = len(wallet_reads)
            wallet_page.wait_for_timeout(2000)
            assert len(wallet_reads) == before, 'Global polling exposed wallet addresses'
            wallet_page.locator('#wallet-receive-list').click()
            wallet_page.locator('#wallet-receive-panel').wait_for(state='visible')
            assert wallet_page.locator('#wallet-address').input_value() == wallets.record['address']
            navigate(wallet_page, 4)
            assert wallet_page.locator('#wallet-address').input_value() == ''
            navigate(wallet_page, 2, 1)
            wallet_page.locator('#wallet-load').locator('..').locator('summary').click()
            wallet_page.locator('#wallet-load').click()
            wallet_page.locator('#wallet-reveal-password').fill('synthetic-password-only')
            wallet_page.locator('#wallet-reveal').click()
            assert wallet_page.locator('#wallet-reveal-password').input_value() == ''
            wallet_page.wait_for_function("() => !document.querySelector('#wallet-seed').disabled")
            pending_seed = []
            wallet_context.route(server.origin + '/api/wallet/seed', lambda route: pending_seed.append(route))
            wallet_page.locator('#wallet-seed').click()
            wallet_page.wait_for_timeout(100)
            assert len(pending_seed) == 1
            navigate(wallet_page, 3)
            pending_seed[0].fulfill(status=200,content_type='application/json',body=json.dumps({
                'wallet_id':wallets.record['wallet_id'],'words':['demo']*25,'challenge':'c'*43,'positions':[2,11,23]}))
            wallet_page.wait_for_timeout(100)
            assert wallet_page.locator('#wallet-words li').count() == 0 and wallet_page.locator('#wallet-seed-panel').is_hidden()
            wallet_context.unroute(server.origin + '/api/wallet/seed')

            def show_again():
                navigate(wallet_page, 2, 1)
                wallet_page.locator('#wallet-load').click()
                wallet_page.locator('#wallet-reveal-password').fill('synthetic-password-only')
                wallet_page.locator('#wallet-reveal').click()
                wallet_page.wait_for_function("() => !document.querySelector('#wallet-seed').disabled")
                wallet_page.locator('#wallet-seed').click()
                wallet_page.locator('#wallet-seed-panel').wait_for(state='visible')
                assert wallet_page.locator('#wallet-words li').count() == 25

            show_again()
            wallet_page.locator('#wallet-hide-seed').click()
            assert wallet_page.locator('#wallet-words li').count() == 0
            show_again()
            wallet_page.evaluate("""() => {
                Object.defineProperty(document, 'hidden', {configurable: true, get: () => true});
                document.dispatchEvent(new Event('visibilitychange'));
            }""")
            assert wallet_page.locator('#wallet-words li').count() == 0
            wallet_page.evaluate("() => {delete document.hidden;}")
            wallet_page.clock.install()
            show_again()
            wallet_page.clock.fast_forward(170001)
            assert wallet_page.locator('#wallet-words li').count() == 0
            assert 'Время показа истекло' in wallet_page.locator('#wallet-backup-state').inner_text()
            navigate(wallet_page, 3, 4)
            pending_list = []
            wallet_context.route(server.origin + '/api/wallet/list', lambda route: pending_list.append(route))
            wallet_page.locator('#wallet-receive-list').click()
            wallet_page.wait_for_timeout(100)
            assert len(pending_list) == 1
            navigate(wallet_page, 4)
            pending_list[0].fulfill(status=200, content_type='application/json', body=json.dumps(wallets.list_wallets()))
            wallet_page.wait_for_timeout(100)
            assert wallet_page.locator('#wallet-address').input_value() == ''
            wallet_context.close()
            print('PASS synthetic wallet: explicit 25 words, 3 backup answers, password clearing, no address polling, late seed ignored',flush=True)

            # READY is read from the server, never from Next or an acknowledgement.
            desk.remote = FakeRemote()
            desk.server_installed = True
            desk.guest_ready = False
            original_run = desk.engine.run
            automatic_ready_calls = []
            def ready_run(remote, command, timeout=60):
                if command.endswith(' status'):
                    automatic_ready_calls.append(command)
                    return 'ГОТОВО: Telegram установлен; Tor подтверждён сейчас'
                return original_run(remote, command, timeout=timeout)
            desk.engine.run = ready_run
            ready_context = browser.new_context()
            ready_page = ready_context.new_page()
            ready_page.on('pageerror', lambda error: errors.append(str(error)))
            ready_page.goto(server.origin + '/#' + desk.nonce)
            navigate(ready_page, 9, 5)
            ready_page.locator('#ready-state').filter(has_text='Telegram установлен; Tor').wait_for()
            assert desk.guest_ready is True and len(automatic_ready_calls) == 1
            ready_page.wait_for_timeout(2000)
            assert len(automatic_ready_calls) == 1, 'Confirmed READY must stop automatic status requests'
            ready_context.close()
            desk.engine.run = original_run
            desk.server_installed = False
            desk.guest_ready = False
            desk.remote = None
            print('PASS automatic READY: actual status response required, no manual acknowledgement', flush=True)

            # Keep deliberate HTTP 403 separate from normal visual-console
            # evidence. These are synthetic credentials, never a user profile.
            desk._set_credentials({'url': 'http://' + 'a' * 56 + '.onion/', 'login': 'demo',
                                   'password': 'demonstration-only', 'totp_secret': 'FAKE-TEST-ONLY',
                                   'otpauth_uri': 'otpauth://totp/TEST'})
            regression_context = browser.new_context()
            regression_page = regression_context.new_page()
            regression_page.on('pageerror', lambda error: errors.append(str(error)))
            regression_context.route(server.origin + '/api/secrets/clear', lambda route: route.fulfill(
                status=403, content_type='application/json', body=json.dumps({'error': 'Проверочный отказ очистки'})))
            regression_page.goto(server.origin + '/#' + desk.nonce)
            navigate(regression_page, 9)
            regression_page.locator('#show-card').click()
            regression_page.locator('#secret-card').wait_for(state='visible')
            regression_page.locator('#clear-card').click()
            regression_page.locator('#notice').filter(has_text='Проверочный отказ очистки').wait_for()
            assert not regression_page.locator('#toast').is_visible(), 'Forbidden clear falsely announced success'
            assert desk.credentials is not None, 'Forbidden clear changed server-side credentials'
            clear_regression['forbidden_403'] = 'notice visible, no success toast, credentials retained'
            regression_context.unroute(server.origin + '/api/secrets/clear')
            regression_page.locator('#show-card').click()
            regression_page.locator('#secret-card').wait_for(state='visible')
            regression_page.locator('#clear-card').click()
            regression_page.locator('#toast').filter(has_text='Карточка удалена').wait_for()
            assert desk.credentials is None, 'Successful clear did not revoke server-side credentials'
            clear_regression['success'] = 'success toast visible, credentials revoked'
            regression_context.close()
            print('PASS credential clear: HTTP403 has no success toast; real successful API clear revokes memory card', flush=True)

            # New automation remains local and uses explicit synthetic records.
            demo = {'url': 'http://' + 'b' * 56 + '.onion/', 'login': 'demo-owner',
                    'password': 'SENTINEL-PASSWORD', 'totp_secret': 'SENTINEL-TOTP',
                    'otpauth_uri': 'SENTINEL-URI'}
            desk.remote = FakeRemote()
            resumed = []
            def resume(remote, emit):
                resumed.append(True)
                return demo
            desk.engine.resume_install = resume
            flow_context = browser.new_context(viewport={'width': 1280, 'height': 900}, reduced_motion='reduce')
            flow = flow_context.new_page()
            flow.on('pageerror', lambda error: errors.append(str(error)))
            flow.goto(server.origin + '/#' + desk.nonce)
            navigate(flow, 8, 3)
            flow.locator('#resume-install').click()
            flow.wait_for_function("() => document.querySelector('#job-message').textContent.includes('Наблюдение восстановлено')")
            assert resumed == [True], 'Resume must call only the existing-job observer once'
            navigate(flow, 10, 1)
            flow.locator('#audit-server').click()
            flow.locator('#safety-report').filter(has_text='Изоляция подтверждена').wait_for()
            capture_action(flow, flow.locator('[data-page="10"]'), LOG / 'app-automation-audit.png')
            navigate(flow, 10, 2)
            flow.locator('#prepare-handoff').click()
            flow.wait_for_function("() => document.querySelector('#handoff-note').value.includes('.onion/')")
            note = flow.locator('#handoff-note').input_value()
            assert demo['url'] in note
            assert all(value not in note for key, value in demo.items() if key != 'url')
            assert flow.locator('#handoff-note').evaluate('(el) => el.scrollTop') == 0, 'The address at the start of the note must be visible'
            capture_action(flow, flow.locator('[data-page="10"]'), LOG / 'app-automation-handoff.png')
            navigate(flow, 12)
            assert flow.locator('#handoff-note').input_value() == '', 'Navigation must clear the private address note'
            navigate(flow, 10, 2)
            pending = []
            flow_context.route(server.origin + '/api/access-note', lambda route: pending.append(route))
            flow.locator('#prepare-handoff').click()
            flow.wait_for_timeout(100)
            assert len(pending) == 1
            navigate(flow, 12)
            pending[0].fulfill(status=200, content_type='application/json', body=json.dumps(desk.access_note()))
            flow.wait_for_timeout(100)
            assert flow.locator('#handoff-note').input_value() == '', 'Late response must not restore the cleared address'
            flow_context.close()
            print('PASS automatic resume/audit and Tails note: no password or TOTP, clear on navigation, stale response ignored', flush=True)
            # Static release evidence uses the standard reduced-motion setting;
            # this separate fixture also settles the real arrival/scroll motion.
            motion_context = browser.new_context(viewport={'width':390,'height':844}, reduced_motion='no-preference')
            motion_page = motion_context.new_page()
            motion_page.on('pageerror', lambda error: errors.append(str(error)))
            motion_page.goto(server.origin + '/#' + desk.nonce)
            assert not motion_page.evaluate("() => matchMedia('(prefers-reduced-motion: reduce)').matches")
            motion_current = navigate(motion_page, 13)
            capture_action(motion_page, motion_current, LOG / 'app-normal-motion-mobile.png')
            motion_context.close()
            print('PASS normal motion: real animation and scroll settle; current mobile navigation card fully visible', flush=True)
            (LOG / 'app-browser.json').write_text(json.dumps({'errors': errors, 'console_errors': console_errors, 'bad_responses': bad_responses, 'external_requests': external_requests, 'screens': measurements, 'capture_checks': capture_checks, 'normal_motion': 'arrival and scroll settled without CSS overrides', 'clear_card_regression': clear_regression, 'usb_writes': len(usb.writes), 'usb_downloads': usb.downloads}, ensure_ascii=False, indent=2))
            assert not errors, repr(errors)
            assert not console_errors, repr({'console': console_errors, 'bad_responses': bad_responses})
            assert not external_requests, repr(external_requests)
            assert len(art_keys)==65, repr(sorted(art_keys))
            assert usb.writes == [] and usb.downloads == 0
            browser.close()
        print('PASS wizard browser errors absent; USB write/download count zero', flush=True)
    finally:
        desk.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == '__main__':
    main()
