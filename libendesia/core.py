
import idaapi
import ida_kernwin
import idautils
import idc
import ida_typeinf
import ida_nalt
import ida_hexrays
import ida_funcs

def get_section_range_by_name(segm_name):
    """ return sections matching by name"""
    for segment in idautils.Segments():
        start_ea = idc.get_segm_start(segment)  
        end_ea = idc.get_segm_end(segment)
        name = idc.get_segm_name(segment) 

        if name == segm_name:
            return start_ea, end_ea
        
    return None, None


def get_functions_by_range(start_ea, end_ea):
    """return all functions in a range """
    functions = []
    if start_ea is None or end_ea is None:
        funcs = idautils.Functions()
    else:
        funcs = idautils.Functions(start=start_ea, end=end_ea)

    for ea in funcs:
        func_name = idc.get_name(ea)
        functions.append([ea, func_name])

    return functions

def get_function_parameters_count(ea):
    """
    Gets the number of parameters for a function at a given address.
    
    :param ea: Effective address of the function
    :return: Number of parameters or None if unknown
    """

    # IMPORTANT NOTE : ida_nalt.get_tinfo(func_tinfo, ea) doesn't work if function isn't decompiled!
    # WE MUST DECOMPILE EACH FUNCTIONS

    ida_hexrays.decompile(ea)
    func_tinfo = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(func_tinfo, ea):
        func_data = ida_typeinf.func_type_data_t()
        if func_tinfo.get_func_details(func_data):
            return func_data.size()  # Number of parameters
    return 0

def get_all_sections():
    """return the list of all binary sections"""
    segm = {}
    for segment in idautils.Segments():
        start_ea = idc.get_segm_start(segment)  
        end_ea = idc.get_segm_end(segment)
        name = idc.get_segm_name(segment) 
        segm[name] = [start_ea, end_ea]
    return segm

def get_instructions_by_function(ea):
    """Retrieves all the instructions within a function at the specified effective address (EA)."""
    func = ida_funcs.get_func(ea)
    if not func:
        return []

    instructions = []
    for addr in idautils.FuncItems(func.start_ea):
        if idc.is_code(idc.get_full_flags(addr)):
            disasm = idc.generate_disasm_line(addr, 0)
            instructions.append((addr, disasm))
    return instructions