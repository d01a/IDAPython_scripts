import idautils 
import idc 
import ida_kernwin
import ida_ua

# get a list of the instructions 

heads = idautils.Heads(idc.get_segm_start(idc.get_screen_ea()) , idc.get_segm_end(idc.get_screen_ea()) )

antiVM = []

# get the Anti-VM instructions

for i in heads:
	if (idc.print_insn_mnem(i) == "sidt" or idc.print_insn_mnem(i) == "sgdt" or idc.print_insn_mnem(i) == "sldt" or idc.print_insn_mnem(i) == "smsw" or idc.print_insn_mnem(i) == "str" or idc.print_insn_mnem(i) == "in" or idc.print_insn_mnem(i) == "cpuid"):
		antiVM.append(i)

print(f"Number of Anti-VM instructions: {len(antiVM)}")

# highlight the instructions and print them in the output screen

for i in antiVM:
	idc.set_color(i, CIC_ITEM, 0x0000ff)
	ida_kernwin.msg("Anti-VM: %08x \t instrution: %s\n" %(i,idc.GetDisasm(i)))
# to get the instruction only, use ida_ua.ua_mnem(<address_of_instruction>) instead of GetDisasm