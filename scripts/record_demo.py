#!/usr/bin/env python3
"""Run a disposable real CLI walkthrough, then render its transcript as GIF/MP4."""

import argparse
import codecs
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import textwrap
import time

from PIL import Image, ImageDraw, ImageFont

PROJECT = Path(__file__).resolve().parent.parent
WIDTH, HEIGHT, FPS = 1200, 800, 8
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def record(command, cwd, env, replies=()):
    """Capture a controlling terminal; send secrets only after hidden prompts."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execve('/bin/sh', ['sh', '-e', '-c', command], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 28, 100, 0, 0))
    decoder = codecs.getincrementaldecoder('utf-8')('replace')
    pending = list(replies)
    full, scanned, events = '', 0, []
    started = time.monotonic()
    complete = False
    try:
        while time.monotonic() - started < 180:
            if not select.select([fd], [], [], 0.2)[0]:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    complete = True
                    break
                raise
            if not data:
                complete = True
                break
            chunk = decoder.decode(data)
            full += chunk
            events.append(chunk)
            if pending and pending[0][0] in full[scanned:]:
                prompt, reply = pending.pop(0)
                scanned = full.index(prompt, scanned) + len(prompt)
                # getpass disables ECHO before printing its prompt. Check it too.
                deadline = time.monotonic() + 2
                while termios.tcgetattr(fd)[3] & termios.ECHO:
                    if time.monotonic() > deadline:
                        raise RuntimeError('Refusing to send a demo password while terminal echo is enabled')
                    time.sleep(0.01)
                os.write(fd, reply.encode() + b'\n')
        if not complete:
            raise RuntimeError('Demo command timed out')
        _, status = os.waitpid(pid, 0)
        pid = 0
        if os.waitstatus_to_exitcode(status) != 0 or pending:
            raise RuntimeError(f'Demo command failed: {command}\n{full}')
        return events
    finally:
        os.close(fd)
        if pid:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def capture():
    with tempfile.TemporaryDirectory(prefix='docvault-demo-') as directory:
        work = (Path(directory) / 'DocVault').resolve()
        work.mkdir()
        for name in ('bin', 'docvault', 'scripts'):
            shutil.copytree(PROJECT / name, work / name,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in ('pyproject.toml', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
                     'install.sh', 'uninstall.sh'):
            shutil.copy2(PROJECT / name, work / name)
        env = dict(os.environ, PATH=f'{work}/.demo/bin:{os.environ["PATH"]}',
                   UV_CACHE_DIR=f'{directory}/uv-cache', UV_PYTHON_DOWNLOADS='never',
                   TERM='xterm-256color', NO_COLOR='1')
        # Random credentials exist only in memory and in the disposable encrypted key.
        words = [line.split()[1] for line in
                 (PROJECT / 'docvault/data/eff_large_wordlist.txt').read_text().splitlines()]
        local = '-'.join(secrets.choice(words) for _ in range(8))
        outer = secrets.token_urlsafe(24)
        scenes = []

        def run(title, note, command, replies=(), step=1):
            print(f'Recording: {title}', flush=True)
            events = record(command, work, env, replies)
            # Shorten disposable absolute paths and remove non-semantic ANSI styling.
            events = [ANSI.sub('', e.replace(str(work), '$PWD').replace(directory, '/tmp/demo'))
                      for e in events]
            if any(password in ''.join(events) for password in (local, outer)):
                raise RuntimeError('A demo credential appeared in the transcript')
            scenes.append(dict(title=title, note=note, command=command, events=events, step=step))

        run('Install locally', 'No sudo needed. Keep the checkout and its .venv in place.',
            './install.sh --bin-dir "$PWD/.demo/bin"\nexport PATH="$PWD/.demo/bin:$PATH"')
        run('Create a local key', 'Choose a strong password. Password input stays hidden.',
            'mkdir -m 700 .demo/key\ndocvault init --key .demo/key/key',
            [('Local key password: ', local), ('Confirm local key password: ', local)], step=2)
        sample = 'Sample documents for the DocVault demo.\n'
        (work / 'Documents').mkdir()
        (work / 'Documents' / 'notes.txt').write_text(sample)
        (work / 'Documents' / 'invoice.txt').write_text('Demo invoice: 42 AUD\n')
        run('Start with sample documents', 'This recording uses two disposable text files.',
            'ls Documents', step=2)
        run('Encrypt and verify', 'Use two independent passwords. --keep retains the originals.',
            'encrypt.sh Documents --key .demo/key/key --keep --key-hint "" --outer-hint ""',
            [('Local 7z key password: ', local), ('Enter 7z password: ', outer),
             ('Confirm 7z password: ', outer)], step=3)
        assert (work / 'Documents.7z').is_file()
        assert (work / 'Documents' / 'notes.txt').read_text() == sample
        credentials = [('Local 7z key password: ', local), ('Enter 7z password: ', outer)]
        run('Verify the portable bundle', 'Both passwords are required. The local key is not needed.',
            'docvault verify Documents.7z', credentials, step=4)
        run('Restore your documents', 'Move originals aside first. Recovery keeps the encrypted bundle.',
            'mv Documents Documents.original\ndecrypt.sh Documents.7z', credentials, step=5)
        run('Check the round trip', 'Restored content matches the original; the bundle is retained.',
            'diff -r Documents.original Documents\ncat Documents/notes.txt\nls Documents.7z', step=5)
        for name in ('notes.txt', 'invoice.txt'):
            assert (work / 'Documents' / name).read_bytes() == (work / 'Documents.original' / name).read_bytes()
        return scenes


def font(size, mono=False):
    paths = (['/System/Library/Fonts/Menlo.ttc',
              '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'] if mono else
             ['/System/Library/Fonts/SFNS.ttf', '/System/Library/Fonts/Helvetica.ttc',
              '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'])
    for path in paths:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    raise RuntimeError('No supported font found; edit font() for your system')


def render(output, scenes):
    title_font, body_font, small_font = font(34), font(20), font(16)
    terminal_font = font(19, True)
    bg, panel, ink, muted, accent = '#0b1220', '#111c2e', '#e6edf7', '#98abc4', '#57e1bc'
    char_width = terminal_font.getlength('M')
    columns = int(1050 / char_width)
    output.mkdir(parents=True, exist_ok=True)

    def frame(title, note, text, step, progress):
        img = Image.new('RGB', (WIDTH, HEIGHT), bg)
        draw = ImageDraw.Draw(img)
        draw.text((44, 26), 'DocVault', font=title_font, fill=ink)
        draw.text((907, 38), 'macOS  /  CLI walkthrough', font=small_font, fill=muted)
        draw.text((44, 87), title, font=title_font, fill=accent)
        draw.text((44, 133), note, font=body_font, fill=muted)
        draw.rounded_rectangle((40, 179, 1160, 663), radius=16, fill=panel, outline='#273750')
        for x, color in ((65, '#ff6a6a'), (88, '#ffc35c'), (111, '#57ce91')):
            draw.ellipse((x, 199, x + 11, 210), fill=color)
        draw.text((151, 195), 'DocVault   /   Terminal', font=small_font, fill=muted)
        draw.line((41, 228, 1159, 228), fill='#273750')
        lines = []
        # Terminal output uses CRLF. A standalone CR updates the current status line.
        for line in text.replace('\r\n', '\n').split('\n'):
            line = line.split('\r')[-1].expandtabs(4)
            lines.extend(textwrap.wrap(line, columns, replace_whitespace=False,
                                       drop_whitespace=False) or [''])
        for i, line in enumerate(lines[-16:]):
            color = accent if line.startswith('$ ') else ink
            if 'verified' in line.lower() or line.startswith('Decrypted:'):
                color = accent
            draw.text((64, 246 + i * 25), line, font=terminal_font, fill=color)
        for i, label in enumerate(('Install', 'Local key', 'Encrypt', 'Verify', 'Restore'), 1):
            x = 44 + (i - 1) * 225
            color = accent if i == step else muted
            draw.rounded_rectangle((x, 691, x + 211, 735), radius=9,
                                   fill='#17372f' if i == step else panel)
            draw.text((x + 14, 703), f'{i:02}  {label}', font=small_font, fill=color)
        draw.text((44, 758), 'Independent passwords. Portable recovery. Verified before cleanup.',
                  font=small_font, fill=muted)
        draw.rectangle((0, 795, int(WIDTH * progress), 799), fill=accent)
        return img

    encoder = subprocess.Popen(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
                                '-f', 'rawvideo', '-pixel_format', 'rgb24',
                                '-video_size', f'{WIDTH}x{HEIGHT}', '-framerate', str(FPS),
                                '-i', '-', '-an', '-c:v', 'libx264', '-preset', 'fast',
                                '-crf', '20', '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
                                str(output / 'demo.mp4')], stdin=subprocess.PIPE)

    def emit(img, duration):
        data = img.tobytes()
        for _ in range(max(1, round(duration * FPS))):
            encoder.stdin.write(data)

    intro = ('# Before you start (setup instructions)\n\n'
             '$ brew install python@3.12 uv sevenzip\n\n'
             '$ export PATH="$(brew --prefix python@3.12)/libexec/bin:$PATH"\n\n'
             '$ git clone https://github.com/evgeny-trushin/DocVault.git\n'
             '$ cd DocVault\n\n'
             '# Next: a real CLI recording in a disposable checkout.\n'
             '# No personal documents or credentials are used.')
    try:
        emit(frame('Install. Protect. Restore.', 'Python 3.12+ and modern 7-Zip. macOS only.', intro, 0, 0), 7)
        for n, scene in enumerate(scenes):
            command = scene['command']
            prefix = ''
            # Animate command entry; output below comes from the actual captured process.
            for end in range(0, len(command) + 8, 8):
                shown = command[:end]
                prefix = '\n'.join('$ ' + line for line in shown.split('\n'))
                emit(frame(scene['title'], scene['note'], prefix, scene['step'],
                           (n + 0.2) / (len(scenes) + 1)), 1 / FPS)
            text = prefix + '\n'
            events = scene['events']
            for event in events:
                text += event
                emit(frame(scene['title'], scene['note'], text, scene['step'],
                           (n + 0.6) / (len(scenes) + 1)), 0.3)
            still = frame(scene['title'], scene['note'], text, scene['step'],
                          (n + 1) / (len(scenes) + 1))
            emit(still, 3.5 if scene['step'] in (2, 3, 5) else 2.5)
            still.save(output / f'preview-{n + 1}.png')
        finish = ('$ docvault --help\n\n'
                  '# Keep both passwords independently.\n'
                  '# --keep retains originals; omit it for verified plaintext cleanup.\n'
                  '# Public hints belong in filenames, never passwords.\n'
                  '# Test recovery and keep independent backups.\n\n'
                  'github.com/evgeny-trushin/DocVault')
        emit(frame('One bundle. Ready to travel.', 'Alpha software. Read the README and recovery guide.',
                   finish, 5, 1), 6)
    finally:
        encoder.stdin.close()
    if encoder.wait() != 0:
        raise RuntimeError('Video encoding failed')
    subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
                    '-i', str(output / 'demo.mp4'), '-filter_complex',
                    '[0:v]fps=8,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];'
                    '[b][p]paletteuse=dither=bayer:bayer_scale=5',
                    '-loop', '0', str(output / 'demo.gif')], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=PROJECT / 'docs' / 'media')
    parser.add_argument('--reuse-recording', action='store_true', help='render the saved, redacted transcript')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('The CLI recording requires macOS')
    if not shutil.which('ffmpeg') or not shutil.which('uv'):
        parser.error('Install ffmpeg and uv before recording')
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    transcript = output / 'demo-transcript.json'
    if args.reuse_recording:
        scenes = json.loads(transcript.read_text())
    else:
        scenes = capture()
        transcript.write_text(json.dumps(scenes, indent=2, ensure_ascii=False) + '\n')
    render(output, scenes)
    print(f'Created {output / "demo.gif"} and {output / "demo.mp4"}', flush=True)


if __name__ == '__main__':
    main()
