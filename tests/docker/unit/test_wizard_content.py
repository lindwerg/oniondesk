"""Novice-facing content must survive template rewrites, not just navigation."""
from html.parser import HTMLParser
from pathlib import Path
import unittest

HTML = Path(__file__).resolve().parents[3] / 'client/ui/index.html'


class Node:
    def __init__(self, tag='', attrs=(), parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children = []
        self.words = []

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def text(self):
        return ' '.join(' '.join(self.words).split())

    def has_class(self, name):
        return name in self.attrs.get('class', '').split()


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.root = Node()
        self.current = self.root
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.current = node

    def handle_endtag(self, tag):
        node = self.current
        while node.parent is not None:
            if node.tag == tag:
                self.current = node.parent
                return
            node = node.parent

    def handle_data(self, data):
        node = self.current
        while node is not None:
            node.words.append(data)
            node = node.parent


class WizardContent(unittest.TestCase):
    def setUp(self):
        self.nodes = list(Document(HTML.read_text()).root.walk())
        self.cards = [node for node in self.nodes if 'data-inner-step' in node.attrs]

    def test_every_action_has_a_title_and_meaningful_result(self):
        self.assertEqual(len(self.cards), 65)
        for card in self.cards:
            with self.subTest(action=card.attrs.get('data-art-key')):
                headings = [node for node in card.children if node.tag == 'h2']
                results = [node for node in card.walk() if node.has_class('expected-result')]
                self.assertEqual(len(headings), 1)
                self.assertGreater(len(headings[0].text()), 8)
                self.assertEqual(len(results), 1)
                self.assertGreater(len(results[0].text()), 35)

    def test_four_server_requirements_are_real_visible_text(self):
        card = next(node for node in self.cards if node.attrs.get('data-art-key') == 'g06-s01')
        grid = next(node for node in card.walk() if node.has_class('check-grid'))
        self.assertEqual(len(grid.children), 4)
        for item in grid.children:
            self.assertGreater(len(item.text()), 35, 'An empty requirement box is not an instruction')
        for requirement in ('Intel', 'AMD', 'KVM', 'Debian 13', '50', '8'):
            self.assertIn(requirement, grid.text())

    def test_visible_checklist_items_and_buttons_are_named(self):
        for grid in (node for node in self.nodes if node.has_class('check-grid')):
            for item in grid.children:
                self.assertTrue(item.text(), 'Visible checklist item lost its text')
        for card in self.cards:
            for button in (node for node in card.walk() if node.tag == 'button'):
                self.assertTrue(button.text() or button.attrs.get('aria-label'), card.attrs['data-art-key'])

    def test_tails_device_roles_and_local_usb_target_stay_explicit(self):
        device = next(node for node in self.cards if node.attrs.get('data-art-key') == 'g00-s02')
        apple = next(node for node in device.walk() if node.attrs.get('id') == 'apple-note')
        for instruction in ('обычной Windows, macOS или Linux', 'этот же компьютер',
                            'Арендованный сервер', 'флешку к нему не подключают',
                            'Android и iPhone не могут загрузить Tails'):
            self.assertIn(instruction, device.text())
        for instruction in ('на этом Mac', 'дополнительный компьютер для входа не нужен',
                            'Пропустите этапы 5 и 11'):
            self.assertIn(instruction, apple.text())
        usb = next(node for node in self.cards if node.attrs.get('data-art-key') == 'g05-s02')
        for instruction in ('от 8 ГБ', 'в этот компьютер, где сейчас открыт мастер',
                            'К арендованному серверу', 'на этапе 11'):
            self.assertIn(instruction, usb.text())

    def test_tails_shutdown_handoff_and_paper_address_remain_available(self):
        shutdown = next(node for node in self.cards if node.attrs.get('data-art-key') == 'g11-s01')
        self.assertRegex(shutdown.text(), r'(?:До выключения|Перед этим этапом)')
        for instruction in ('сервер на этапах 8–10', 'PDF-инструкцию', 'на телефоне', 'распечатайте этап 11',
                            'мастер в Tails автоматически не продолжится', 'это может быть этот же компьютер'):
            self.assertIn(instruction, shutdown.text())
        address = next(node for node in self.cards if node.attrs.get('data-art-key') == 'g11-s06')
        for instruction in ('на втором USB', '«Файлы»', 'полный onion-адрес',
                            'памятка распечатана', 'с бумаги', 'Файл и второй USB для этого не нужны'):
            self.assertIn(instruction, address.text())


if __name__ == '__main__':
    unittest.main()
