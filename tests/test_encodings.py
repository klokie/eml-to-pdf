import unittest
from pathlib import Path
import email
from html import escape
from eml_to_pdf import eml_to_pdf
from . import generate_test_emls
import os


eml_path = Path('tests/test_data')

# These mails definitions are used to generate emls in test data
mails = {m.filename: m for m in generate_test_emls.mails}

# Adding two extra email msgs. They are real eml's.
more_mails = mails | {
    "simple_plain_and_html_embedded_img.eml":
    generate_test_emls.TestMail(
        _from="First Last <first.last@outlook.com>",
        to="\"Last, First\" <first.last@outlook.com>",
        subject="This is a test mail with embedded imgs",
        msg="",
        enc="utf-8",
        filename="simple_plain_and_html_embedded_img.eml"
    ),
    "train_ticket.eml": generate_test_emls.TestMail(
        to="first.last@outlook.com",
        _from="\"NMBS/SNCB:\" <no-reply@belgiantrain.be>",
        subject="NMBS Mobile Ticket NL",
        msg="",
        enc="utf-8", filename="train_ticket.eml"
    ),
    "plain_lorem_ipsum.eml": generate_test_emls.TestMail(
        to="recipient@example.com",
        _from="sender@example.com",
        subject="Test Email with Lorem Ipsum",
        msg="",
        enc="utf-8", filename="plain_lorem_ipsum.eml"
    ),
}


def get_tgt_html(html_path: Path) -> str:
    """Return content of html_path as string."""
    with open(eml_path / html_path) as f:
        html_str = f.read()
    return html_str


class TestEmls(unittest.TestCase):
    def test_headers(self):
        """Headers should remain the same from src data and eml files."""
        infiles = eml_to_pdf.get_filepaths(Path(os.getcwd()))
        for eml in infiles:
            with open(eml) as f:
                eml_msg = email.message_from_file(f)
            src_eml = more_mails.get(eml.name)
            if not src_eml:
                continue
            with self.subTest(eml=eml):
                # Header fields are not named consistently. Tuples the contain
                # header attr names depending on context.
                for h in [('_from', 'from'),
                          ('to', 'to'),
                          ('subject', 'subject')
                          ]:
                    src_head = escape(getattr(src_eml, h[0]))
                    eml_head = eml_to_pdf.header_to_html(eml_msg.get(h[1]))
                    self.assertEqual(src_head, eml_head)

    def test_plain_text(self):
        """Plain text file body should render as html."""
        pt_emls = [
                ('plain_lorem_ipsum.eml',
                 get_tgt_html(Path('plain_lorem_ipsum.html'))),
                ('plain_text.eml',
                 get_tgt_html(Path('plain_text.html'))),
                ('mixed_plain_html_smiley_embedded.eml',
                 get_tgt_html(Path('mixed_plain_html_smiley_embedded.html'))),
                ]

        for eml in pt_emls:
            with open(eml_path / Path(eml[0])) as f:
                eml_msg = email.message_from_file(f)
            with self.subTest(eml=eml[0]):
                eml_html = eml_to_pdf.html_from_eml(eml_msg, eml[0])
                self.assertEqual(eml_html, eml[1].strip())


if __name__ == '__main__':
    unittest.main()
