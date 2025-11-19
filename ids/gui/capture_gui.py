#!/usr/bin/env python3
"""GUI module for IDS capture.

This module provides `run()` which launches the Tk GUI. It is separated
from the `scripts/` launcher so the GUI can be imported and tested.
"""

import os
import sys
import signal
import subprocess
import threading
import queue
import json
import socket
import shutil
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog


class CaptureGUI:
    def __init__(self, root):
        self.root = root
        root.title('IDS Capture GUI')

        frm = ttk.Frame(root, padding=10)
        frm.grid(sticky='nsew')

        # Backend selection + status
        ttk.Label(frm, text='Backend:').grid(column=0, row=0, sticky='w')
        self.backend_var = tk.StringVar(value='scapy')
        self.backend_combo = ttk.Combobox(frm, textvariable=self.backend_var, state='readonly')
        self.backend_combo['values'] = ('scapy', 'pyshark', 'socket')
        self.backend_combo.grid(column=1, row=0, sticky='we')
        self.backend_status_label = ttk.Label(frm, text='')
        self.backend_status_label.grid(column=2, row=0, sticky='w', padx=(6, 0))
        self.backend_combo.bind('<<ComboboxSelected>>', lambda e: self.update_backend_status())
        self.check_backends_btn = ttk.Button(frm, text='Check', command=self.refresh_backends)
        self.check_backends_btn.grid(column=3, row=0, sticky='we', padx=(6, 0))

        # Interface selection
        ttk.Label(frm, text='Interface:').grid(column=0, row=1, sticky='w')
        self.iface_var = tk.StringVar(value='lo')
        self.iface_combo = ttk.Combobox(frm, textvariable=self.iface_var, state='readonly')
        self.iface_combo.grid(column=1, row=1, sticky='we')
        self.refresh_btn = ttk.Button(frm, text='Refresh', command=self.refresh_interfaces)
        self.refresh_btn.grid(column=2, row=1, sticky='we', padx=(6, 0))

        # Control buttons
        self.start_btn = ttk.Button(frm, text='Start', command=self.start_capture)
        self.start_btn.grid(column=0, row=2, sticky='we', pady=(6, 0))
        self.stop_btn = ttk.Button(frm, text='Stop', command=self.stop_capture, state='disabled')
        self.stop_btn.grid(column=1, row=2, sticky='we', pady=(6, 0))
        self.switch_btn = ttk.Button(frm, text='Switch', command=self.switch_interface, state='disabled')
        self.switch_btn.grid(column=2, row=2, sticky='we', padx=(6, 0), pady=(6, 0))

        # Status and output
        self.status_var = tk.StringVar(value='Stopped')
        ttk.Label(frm, textvariable=self.status_var).grid(column=0, row=3, columnspan=2, sticky='w')

        self.txt = scrolledtext.ScrolledText(frm, width=100, height=20)
        self.txt.grid(column=0, row=4, columnspan=4, pady=(8, 0))

        # Save options
        self.save_var = tk.BooleanVar(value=False)
        self.save_check = ttk.Checkbutton(frm, text='Save JSON', variable=self.save_var, command=self._on_save_toggle)
        self.save_check.grid(column=0, row=5, sticky='w', pady=(8, 0))
        self.save_path_var = tk.StringVar(value='')
        self.save_entry = ttk.Entry(frm, textvariable=self.save_path_var)
        self.save_entry.grid(column=1, row=5, sticky='we', pady=(8, 0))
        self.browse_btn = ttk.Button(frm, text='Browse', command=self._browse_save)
        self.browse_btn.grid(column=2, row=5, sticky='we', padx=(6, 0), pady=(8, 0))

        frm.columnconfigure(1, weight=1)
        root.protocol('WM_DELETE_WINDOW', self.on_close)

        # runtime state
        self.proc = None
        self.out_thread = None
        self.queue = queue.Queue()
        self._poll_job = None
        self.save_filehandle = None

        # initialize UI
        self.refresh_interfaces()
        self.refresh_backends()

    # Interface discovery
    def refresh_interfaces(self):
        try:
            ifs = [name for _idx, name in socket.if_nameindex()]
        except Exception:
            ifs = []

        if not ifs:
            ifs = ['lo']

        self.iface_combo['values'] = ifs
        current = self.iface_var.get()
        if current not in ifs:
            self.iface_var.set('lo' if 'lo' in ifs else ifs[0])

    # Backend checks
    def refresh_backends(self):
        self.backend_availability = {}
        # scapy
        try:
            import scapy.all as scapy_all  # noqa: F401
            self.backend_availability['scapy'] = (True, 'ok')
        except Exception as e:
            self.backend_availability['scapy'] = (False, f'missing scapy: {e}')

        # pyshark + tshark
        try:
            import pyshark  # noqa: F401
            tshark_path = shutil.which('tshark')
            if not tshark_path:
                self.backend_availability['pyshark'] = (False, 'missing tshark')
            else:
                self.backend_availability['pyshark'] = (True, 'ok')
        except Exception as e:
            self.backend_availability['pyshark'] = (False, f'missing pyshark: {e}')

        # socket raw capability
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            self.backend_availability['socket'] = (True, 'ok')
        except PermissionError:
            self.backend_availability['socket'] = (False, 'requires CAP_NET_RAW or root')
        except Exception as e:
            self.backend_availability['socket'] = (False, f'unavailable: {e}')

        self.update_backend_status()

    def update_backend_status(self):
        backend = self.backend_var.get()
        avail, reason = self.backend_availability.get(backend, (False, 'unknown'))
        self.backend_status_label.config(text=('OK' if avail else f'Unavailable: {reason}'))
        if not avail:
            self.start_btn.config(state='disabled')
        else:
            self.start_btn.config(state='normal')

    # Save helpers
    def _on_save_toggle(self):
        if self.save_var.get() and not self.save_path_var.get():
            self._browse_save()

    def _browse_save(self):
        path = filedialog.asksaveasfilename(title='Save JSON lines to', defaultextension='.json', filetypes=[('JSON', '*.json'), ('All files', '*.*')])
        if path:
            self.save_path_var.set(path)

    # Capture control
    def start_capture(self):
        if self.proc is not None:
            messagebox.showinfo('Info', 'Capture already running')
            return

        backend = self.backend_var.get()
        interface = self.iface_var.get() or None

        # runner moved into package at ids/runner_capture.py
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        runner = os.path.join(repo_root, 'ids', 'runner_capture.py')
        cmd = [sys.executable, runner, '--backend', backend]
        if interface:
            cmd += ['--interface', interface]

        try:
            env = os.environ.copy()
            existing = env.get('PYTHONPATH', '')
            if repo_root not in existing.split(os.pathsep):
                env['PYTHONPATH'] = repo_root + (os.pathsep + existing if existing else '')

            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, cwd=repo_root, env=env)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to start capture: {e}')
            self.proc = None
            return

        # optional save file
        if self.save_var.get() and self.save_path_var.get():
            try:
                self.save_filehandle = open(self.save_path_var.get(), 'a', encoding='utf-8')
            except Exception as e:
                messagebox.showerror('Error', f'Cannot open save file: {e}')
                self.save_filehandle = None

        self.status_var.set(f'Started ({backend})')
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.txt.insert('end', f'=== Started {backend} capture (interface={interface}) ===\n')
        self.txt.see('end')

        self.out_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.out_thread.start()
        self._poll_queue()
        self.switch_btn.config(state='normal')

    def stop_capture(self):
        if not self.proc:
            return
        self.txt.insert('end', 'Stopping capture...\n')
        self.txt.see('end')
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except Exception:
                self.proc.kill()
        except Exception as e:
            print('Stop error', e)

        self.proc = None
        self.status_var.set('Stopped')
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.switch_btn.config(state='disabled')

        if self.save_filehandle:
            try:
                self.save_filehandle.close()
            except Exception:
                pass
            self.save_filehandle = None

    def switch_interface(self):
        if not self.proc:
            messagebox.showinfo('Info', 'No capture running; use Start to begin.')
            return

        new_iface = self.iface_var.get() or None
        backend = self.backend_var.get()
        self.txt.insert('end', f'--- Switching capture to interface={new_iface} ({backend}) ---\n')
        self.txt.see('end')
        self.stop_capture()
        self.start_capture()

    def _read_stdout(self):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            if self.save_filehandle:
                try:
                    self.save_filehandle.write(line)
                    self.save_filehandle.flush()
                except Exception:
                    pass
            self.queue.put(('out', line))

        if self.proc and self.proc.stderr:
            for line in self.proc.stderr:
                self.queue.put(('err', line))

        self.queue.put(('finished', ''))

    def _poll_queue(self):
        try:
            while True:
                typ, line = self.queue.get_nowait()
                if typ == 'out':
                    try:
                        obj = json.loads(line)
                        pretty = json.dumps(obj, indent=2)
                        self.txt.insert('end', pretty + '\n')
                    except Exception:
                        self.txt.insert('end', line)
                elif typ == 'err':
                    self.txt.insert('end', '[ERR] ' + line)
                elif typ == 'finished':
                    self.txt.insert('end', '=== Capture process exited ===\n')
                    self.stop_capture()
                self.txt.see('end')
        except queue.Empty:
            pass

        self._poll_job = self.root.after(200, self._poll_queue)

    def on_close(self):
        if self.proc:
            if not messagebox.askyesno('Exit', 'Capture is running. Stop and exit?'):
                return
            self.stop_capture()

        if self._poll_job:
            self.root.after_cancel(self._poll_job)
        self.root.destroy()


def run():
    root = tk.Tk()
    app = CaptureGUI(root)

    def _handle_sigint(signum, frame):
        try:
            root.quit()
        except Exception:
            pass

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        try:
            root.quit()
        except Exception:
            pass


if __name__ == '__main__':
    run()
