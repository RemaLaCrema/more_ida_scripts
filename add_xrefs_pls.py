# This simple plugin just adds XRef to function number
# to the beginning of the function.


import idautils
import idaapi
import idc

def add_xrefs():
    for func in idautils.Functions():
        funcName = idc.get_func_name(func)
        xRefCount = len(list(idautils.XrefsTo(func)))
        idc.set_name(func, "_" + str(xRefCount) + "_" + funcName)
        
class add_xrefs_t(idaapi.plugin_t):
    comment = "Adding Xrefs count to func names"
    help = ""
    wanted_name = "add_xrefs"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_UNL
    
    def init(self):
        return idaapi.PLUGIN_OK        

    def run(self, arg):
        add_xrefs()

    def term(self):
        return

def PLUGIN_ENTRY():
    return add_xrefs_t()
