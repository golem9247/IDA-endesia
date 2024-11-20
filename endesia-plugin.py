# -*- encoding: utf8 -*-
#
# IDA plugin definition.

import idaapi
from libendesia.console import Console, is_using_pyqt5
from PyQt5.QtWidgets import QApplication

class Endesia(idaapi.plugin_t):
    wanted_name = "Endesia"
    wanted_hotkey = "Shift-F2"
    flags = idaapi.PLUGIN_FIX
    comment = ""
    help = "Starts an Endesia qtconsole in IDA Pro"
    
    def init(self):
        self.widget = None
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        if self.widget is None:
            self.widget = Console()
        self.widget.Show()

    def term(self):
        if self.widget:
            self.widget.Close(0)
            self.widget = None

def PLUGIN_ENTRY():
    return Endesia()

# Links Qt's event loop with asyncio's event loop. This allows asyncio to
# work properly, which is required for ipykernel >= 5 (more specifically,
# because ipykernel uses tornado, which is backed by asyncio).
def _setup_asyncio_event_loop():
    import qasync
    import asyncio
    if isinstance(asyncio.get_event_loop(), qasync.QEventLoop):
        print("Note: qasync event loop already set up.")
    else:
        qapp = QApplication.instance()
        loop = qasync.QEventLoop(qapp, already_running=True)
        asyncio.set_event_loop(loop)

if QApplication.instance() and is_using_pyqt5():
    _setup_asyncio_event_loop()
