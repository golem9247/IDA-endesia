import idaapi
import idc

class ResultFunction(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Function Name", idaapi.Choose.CHCOL_PLAIN|12]
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [hex(res[0]), res[1]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0