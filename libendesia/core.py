
import idaapi
import ida_kernwin
import idautils
import idc
import ida_typeinf
import ida_nalt
import ida_hexrays


def get_section_range_by_name(segm_name):
    for segment in idautils.Segments():
        start_ea = idc.get_segm_start(segment)  
        end_ea = idc.get_segm_end(segment)
        name = idc.get_segm_name(segment) 

        if name == segm_name:
            return start_ea, end_ea
        
    return None, None


def get_functions_by_range(start_ea, end_ea):

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
