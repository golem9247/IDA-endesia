# -*- encoding: utf8 -*-

import idaapi
import idc

from libendesia import core
from libendesia import results
from libendesia.util import *

import colorama
colorama.init(autoreset=True)

from colorama import Fore
from colorama import Style

from copy import copy
import re

red = Fore.RED
reset = Style.RESET_ALL
green = Fore.GREEN
yellow = Fore.YELLOW

def colorama_update(message):
    message = (
            message.replace(red, '<span style="color:red;">')
                   .replace(green, '<span style="color:green;">')
                   .replace(yellow, '<span style="color:orange;">')
                   .replace(reset, '</span>')
        )
    return message

def is_using_pyqt5():
    if hasattr(idaapi, "get_kernel_version"):
        _ida_version_major, _ida_version_minor = map(int, idaapi.get_kernel_version().split("."))
        return _ida_version_major > 6 or (_ida_version_major == 6 and _ida_version_minor >= 9)
    else:
        return False

if is_using_pyqt5():
    from PyQt5 import QtGui, QtWidgets, QtCore
else:
    from PySide import QtGui, QtCore

import sys

operations = {
        "xor_cst": ["xor","eor"],
        "mov_cst": ["mov"],
        "sub_cst": ["sub"],
        "add_cst": ["add"],
        "mul_cst": ["imul"],  
        "div_cst": ["idiv"], 
        "shift_right_cst": ["shr"],
        "shift_left_cst": ["shl"]
    }

class Argument():
    def __init__(self, cmd):
        self.cmd = cmd
        self.root_cmd = self.cmd.split(" ")[0]

        self.p_attr = {}

    def get_expr_args(self):
        """
        Parses the given expression into a dictionary format.
        """
        pattern = r'(\w+)\((.*?)\)'
        matches = re.findall(pattern, self.cmd)
        p_attr = {}

        for primary, secondary in matches:
            secondary_pattern = r'(\w+):([^\s]+)'
            secondary_matches = re.findall(secondary_pattern, secondary)
            p_attr[primary] = {
                key: value for key, value in secondary_matches
            }
        
        self.p_attr = p_attr


class HistoryLineEdit(QtWidgets.QLineEdit if is_using_pyqt5() else QtGui.QLineEdit):
    """
    A QLineEdit subclass that handles command history navigation with Up/Down keys.
    """
    def __init__(self, parent=None):
        super(HistoryLineEdit, self).__init__(parent)
        self.history = []  # Command history
        self.history_index = -1  # Current position in history

    def add_to_history(self, command):
        """
        Adds a new command to the history, avoiding duplicates.
        """
        if command and (len(self.history) == 0 or command != self.history[-1]):
            self.history.append(command)
        self.history_index = len(self.history)  # Reset index to the end

    def keyPressEvent(self, event):
        """
        Handles Up/Down key events for history navigation.
        """
        if event.key() == QtCore.Qt.Key_Up:
            # Navigate to the previous command
            if self.history and self.history_index > 0:
                self.history_index -= 1
                self.setText(self.history[self.history_index])
        elif event.key() == QtCore.Qt.Key_Down:
            # Navigate to the next command
            if self.history and self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.setText(self.history[self.history_index])
            else:
                self.history_index = len(self.history)
                self.clear()
        else:
            super(HistoryLineEdit, self).keyPressEvent(event)

class Console(idaapi.PluginForm):
    
    def __init__(self, *args):
        super(Console, self).__init__(*args)
        self.text_edit = None
        self.input_line = None

        self.completer = None
        self.command_list = ["clear", "examples", "help", "eval_list", "sections", "uncolor"]

        self.highlighted_ea = []

        self.attributes_functions = {
            "range" : ["Filter by an adress range", "hex-hex"],
            "params" : ["Filter by number of parameters in functions signature", "int/hex"],
            "section" : ["Filter by section name", "str"],
            "block_eq" : ["Filter by number of blocks in flowgraph : equal", "int/hex"],
            "block_more" : ["Filter by number of blocks in flowgraph : superior scrict", "int/hex"],
            "block_less" : ["Filter by number of blocks in flowgraph : inferior scrict", "int/hex"],
            "xor_cst" : ["Filter by a XOR const instruction", "int/hex"],
            "mov_cst" : ["Filter by a MOV const instruction", "int/hex"],
            "sub_cst" : ["Filter by a SUB const instruction", "int/hex"],
            "add_cst" : ["Filter by a add const instruction", "int/hex"],
            "mul_cst" : ["Filter by a MUL const instruction", "int/hex"],
            "div_cst" : ["Filter by a DIV const instruction", "int/hex"],
            "shift_right_cst" : ["Filter by a shift to right const instruction", "int/hex"],
            "shift_left_cst" : ["Filter by a shift to left const instruction", "int/hex"],
        }

        self.decompilation_warn = 1
    
    def OnCreate(self, form):
        try:
            if is_using_pyqt5():
                self.parent = self.FormToPyQtWidget(form, ctx=sys.modules[__name__])
            else:
                self.parent = self.FormToPySideWidget(form, ctx=sys.modules[__name__])
            layout = self._createConsoleWidget()
            
            self.parent.setLayout(layout)
        except:
            import traceback
            print(traceback.format_exc())

    def _createConsoleWidget(self):
        if is_using_pyqt5():
            layout = QtWidgets.QVBoxLayout()
            self.text_edit = QtWidgets.QTextEdit()
            self.input_line = HistoryLineEdit()
        else:
            layout = QtGui.QVBoxLayout()
            self.text_edit = QtGui.QTextEdit()
            self.input_line = HistoryLineEdit()

        self.text_edit.setReadOnly(True)
        self.text_edit.setPlaceholderText("Endesia Console Output")
        
        self.input_line.setPlaceholderText("Enter command here...")
        self.input_line.returnPressed.connect(self.handle_input)

        self._setup_autocompletion()

        layout.addWidget(self.text_edit)
        layout.addWidget(self.input_line)

        return layout

    def _setup_autocompletion(self):
        """
        Sets up autocompletion for the input line using QCompleter.
        """
        if is_using_pyqt5():
            self.completer = QtWidgets.QCompleter(self.command_list)
        else:
            self.completer = QtGui.QCompleter(self.command_list)
        
        self.completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)  # Case-insensitive matching
        self.completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)  # Popup style completion
        self.input_line.setCompleter(self.completer)
    
    def handle_input(self):
        """
        Handles user input when they press Enter in the input line.
        """
        user_input = self.input_line.text()
        if user_input.strip():  # Process non-empty input
            self.log_message(f"-> {user_input}")
            self.input_line.add_to_history(user_input)
            self.process_command(user_input)
        self.input_line.clear()

    def process_command(self, command):
        """
        Processes a command entered in the console input line.
        Extend this method with custom commands.
        """

        args = Argument(command)

        match args.root_cmd:
            case "clear":
                self.text_edit.clear()
            case "help":
                self.handler_help()
            case "examples":
                self.handler_examples()
            case "eval":
                self.handler_eval_expr(args)
            case "sections":
                self.handler_sections()
            case "eval_list":
                self.handler_eval_list()
            case "uncolor":
                self.handler_uncolor()
            case default:
                self.log_message(f"{red}Unknown command:{reset} {command}")
                self.log_message("")

    def log_message(self, message):
        """
        Logs a message to the console output area.
        """
        message = colorama_update(message)
        self.text_edit.append(message)

    def Show(self, name="Endesia Console"):
        form = idaapi.PluginForm.Show(self, name)
        self.log_message(f"{green}--------- Endesia Console Started ------------")
        self.handler_help()
        return form

    def OnClose(self, form):
        return
    
    def ASS_VALID(self, **kwargs):
        err = kwargs.get("err", "[general err]")
        for arg in kwargs:
            v_arg = kwargs.get(arg, None)
            if v_arg is None:
                self.log_message(f"{red} {arg} is None ! err={err}")
                return 1
            
        return 0


    #------- HANDLER COMMANDS SECTIONS

    # CMD : EXAMPLES
    def handler_examples(self):
        self.log_message("Examples Expression :")
        self.log_message(f"  list all functions with 2 parameters --> {green}eval F(param:2)")
        self.log_message(f"  list all functions with 2 parameters in section .text --> {green}eval F(param:2 section:.text)")
        self.log_message(f"  list all functions with 4 parameters in range 0xffba-0xfffc --> {green}eval F(param:4 range:0xffba-0xfffc)")
        self.log_message(f"  list all functions with xor X, 0xff01 instructions --> {green}eval F(xor_cst:0xff01)")
        self.log_message("")

    # CMD : HELP
    def handler_help(self):

        self.log_message("Available commands :")
        self.log_message(f"  -> {green}clear{reset} : clear console")
        self.log_message(f"  -> {green}eval{reset} : Evaluate an expression. Type examples for some expressions examples")
        self.log_message(f"  -> {green}examples{reset} : Expressions examples.")
        self.log_message(f"  -> {green}sections{reset} : List binary sections.")
        self.log_message(f"  -> {green}eval_list{reset} : List all attributes for expressions")
        self.log_message(f"  -> {green}uncolor{reset} : Remove all generated color created by matching instructions const")
        self.log_message("")

    def handler_uncolor(self):

        for ea in self.highlighted_ea:
            idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFF)
        self.highlighted_ea = []
        self.log_message("Uncolored all instructions highlighted")

    # CMD : SECTIONS
    def handler_sections(self):
        sections = core.get_all_sections()
        for section in sections:
            self.log_message(f"  -> {section} : {phex(sections[section][0])}-{phex(sections[section][1])}")

    # CMD : EVAL_LIST
    def handler_eval_list(self):
        self.log_message("")
        self.log_message(f"Functions evaluation : {green}F")
        for attr in self.attributes_functions:
            desc,type_ = self.attributes_functions[attr]
            self.log_message(f" --- Attribute -> {yellow}{attr}{reset} :{desc} ({type_})")

    # CMD : EVAL
    def handler_eval_expr(self, args):

        args.get_expr_args()

        if (len(args.p_attr) == 0):
            self.log_message(f"{red}Couldn't evaluate Expression{reset}")
            return

        for p_attr in args.p_attr:
            p_attr_g = args.p_attr[p_attr]
        
            match p_attr:
                case 'F':
                    self._function_eval(p_attr_g)
                case default:
                    self.log_message(f"Unknow Expression {yellow}{p_attr}{reset} ! Will not evaluate")

        self.log_message("")

    #------- CORE COMMANDS SECTIONS

    def _function_eval(self, params):
        
        start_ea, end_ea = None,None
        if 'section' in params and 'range' in params:
            self.log_message(f"{yellow}Warn : 'section' is useless as 'range' will override it")

        if 'section' in params:
            start_ea,end_ea = core.get_section_range_by_name(params['section'])
            if(self.ASS_VALID(start_ea=start_ea, end_ea=end_ea, err="bad section name")):
                return
            params.pop('section')
            
        if 'range' in params:
            range_args = params['range']
            if "-" not in range_args:
                self.log_message(f"{red} : 'range' parameters isn't valid, format -> range:0xY-0xZ")
                return
            
            range_args_r = range_args.replace(" ","").split("-")
            start_ea = int(range_args_r[0],16)
            end_ea =   int(range_args_r[1],16)
            params.pop('range')

        functions = core.get_functions_by_range(start_ea, end_ea)

        if "params" in params:
            functions_params_filtered = []

            params_nb = cast_from_str(params['params'])
            if self.decompilation_warn:
                self.log_message(f"{yellow}Warn : 'params' evaluation internals function force IDA to decompile functions to get some typeinfo structs. This process may be long")
                self.decompilation_warn = 0

            for function in functions:
                size = core.get_function_parameters_count(function[0])
                if size == params_nb:
                    functions_params_filtered.append(function)

            functions = functions_params_filtered
            params.pop('params')

        if any(op in params for op in operations.keys()):
            params_ = copy(params)
            for param in params_:
                if param in operations.keys():
                    const = cast_from_str(params_[param])

                    filtered_functions = []

                    for func in functions:
                        m_cgr = instr_match_op_cst(core.get_instructions_by_function(func[0]), operations[param], const)
                        if m_cgr:
                            idc.set_color(m_cgr, idc.CIC_ITEM, 0x008000)
                            filtered_functions.append(func)
                            self.highlighted_ea.append(m_cgr)

                    functions = filtered_functions
                    params.pop(param)

        if any(op in params for op in ["block_eq", "block_more", "block_less"]):
            params_ = copy(params)
            for param in params_:
                if param in ["block_eq", "block_more", "block_less"]:
                    const = cast_from_str(params_[param])

                    filtered_functions = []
                    for func in functions:
                        nb_block = core.get_number_of_blocks(func[0])
                        match param:
                            case "block_eq":
                                if nb_block == const:
                                    filtered_functions.append(func) 
                            case "block_more":
                                if nb_block > const:
                                    filtered_functions.append(func) 
                            case "block_less":
                                if nb_block < const:
                                    filtered_functions.append(func) 

                    functions = filtered_functions
                    params.pop(param)


        if len(params) != 0:
            self.log_message(f"{red} Extra attributes found! Those attributes couldn't be processed :")
            for param in params:
                self.log_message(f"{red} -> Unknow attr : {param}")

        c = results.ResultFunction("Expression results", functions)
        _ = c.show()

        self.log_message(f"{green} Evaluation : OK | {len(functions)} results")
        