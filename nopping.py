import ida_expr
import ida_kernwin
import idc
import ida_bytes
import ida_kernwin

ida_expr.compile_idc_text('static n_key() { RunPythonStatement("nopping()"); }')
ida_kernwin.add_idc_hotkey("Alt-N", "n_key")

def nopping():
    start = idc.get_screen_ea()
    end = idc.next_head (start)
    for ea in range(start,end):
        ida_bytes.patch_byte(ea,0x90)
    ida_kernwin.jumpto(end)
    ida_kernwin.refresh_idaview_anyway()