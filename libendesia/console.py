# -*- encoding: utf8 -*-

import idaapi
import idc

from libendesia import core
from libendesia import results
from libendesia.util import *

import colorama
colorama.init(autoreset=True)
from colorama import Fore,Style
import re
import os

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

operation_register_common = {
        "xor": ["xor","eor"],
        "mov": ["mov"],
        "sub": ["sub"],
        "add": ["add"],
        "mul": ["mul"],  
        "div": ["div"], 
        "shr": ["shr"],
        "shl": ["shl"]
    }

class Argument:
    def __init__(self, cmd):
        self.cmd = cmd
        self.root_cmd = self.cmd.split(" ")[0]
        self.p_args = list()

    def get_expr_args(self) -> int:

        expr = self.cmd[len(self.root_cmd):].strip()

        tokens = re.split(r'([&|])', expr)
        for i, token in enumerate(tokens):
            token = token.strip()
            if not token or token in ['&', '|']:
                continue

            match = re.match(r'(\w+)\s*(<=|>=|=|<|>|!=)\s*([\w.]+(?:-\w+)?)', token)
            if not match:
                return -1

            arg_name, operator, arg_value = match.groups()
            relation_next = None

            if i + 1 < len(tokens):
                relation_next = 'and' if tokens[i + 1] == '&' else 'or'

            self.p_args.append({
                "arg_name": arg_name,
                "arg_value": arg_value,
                "operator": operator,
                "relation_next": relation_next
            })
            
        return 0

class HistoryLineEdit(QtWidgets.QLineEdit if is_using_pyqt5() else QtGui.QLineEdit):
    """
    A QLineEdit subclass that handles command history navigation with Up/Down keys.
    """
    def __init__(self, parent=None):
        super(HistoryLineEdit, self).__init__(parent)
        self.history = []  # Command history
        self.history_index = -1  # Current position in history

        self.history_file = "/tmp/.endesia.history"
        self.map_history()


    def map_history(self):

        if not os.path.exists(self.history_file):
            self.fd = open(self.history_file,"w")
        else:
            self.fd= open(self.history_file,"r")
            size = self.fd.tell()
            if size > 10000:
                os.unlink(self.history_file)
                self.fd = open(self.history_file,"w")
                return

            self.history = self.fd.readlines()
            self.fd.close()
            self.fd = open(self.history_file,"a")
            self.history_index = len(self.history)

    def __del__(self):
        self.fd.close()

    def add_to_history(self, command):
        """
        Adds a new command to the history, avoiding duplicates.
        """
        if command and (len(self.history) == 0 or command != self.history[-1]):
            self.history.append(command)
        self.history_index = len(self.history)  # Reset index to the end
        self.fd.write(command+"\n")
        self.fd.flush()

    def keyPressEvent(self, event):
        """
        Handles Up/Down key events for history navigation.
        """
        if event.key() == QtCore.Qt.Key_Up:
            # Navigate to the previous command
            if self.history and self.history_index > 0:
                self.history_index -= 1
                self.setText(self.history[self.history_index].strip())
        elif event.key() == QtCore.Qt.Key_Down:
            # Navigate to the next command
            if self.history and self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.setText(self.history[self.history_index].strip())
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
            "param" : ["Filter by number of parameters in functions signature", "int/hex"],
            "section" : ["Filter by section name", "str"],
            "block" : ["Filter by number of blocks in flowgraph : equal", "int/hex"],
            "xor" : ["Filter by a XOR const instruction", "int/hex"],
            "mov" : ["Filter by a MOV const instruction", "int/hex"],
            "sub" : ["Filter by a SUB const instruction", "int/hex"],
            "add" : ["Filter by a add const instruction", "int/hex"],
            "mul" : ["Filter by a MUL const instruction", "int/hex"],
            "div" : ["Filter by a DIV const instruction", "int/hex"],
            "shr" : ["Filter by a shift to right const instruction", "int/hex"],
            "shl" : ["Filter by a shift to left const instruction", "int/hex"],
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

    def err(self, message):
        self.log_message(f"{red}{message}")
    
    def warn(self, message):
        self.log_message(f"{yellow}{message}")
    
    def success(self, message):
        self.log_message(f"{green}{message}")

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
        self.log_message(f"  list all functions with 2 parameters --> {green}eval param=2")
        self.log_message(f"  list all functions with 4 parameters in range 0xffba-0xfffc --> {green}eval param=4 range=0xffba-0xfffc)")
        self.log_message(f"  list all functions with xor X, 0xff01 instructions --> {green}eval xor=0xff01)")
        self.log_message(f"  list all functions in .text that have a xor const with 0xffaabbcc OR 0xffaabbdd --> {green}eval section=.text&xor=0xffaabbcc|xor=0xffaabbdd")
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

    # CMD : UNCOLOR
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
        for attr in self.attributes_functions:
            desc,type_ = self.attributes_functions[attr]
            self.log_message(f" --- Attribute -> {yellow}{attr}{reset} :{desc} ({type_})")

    # CMD : EVAL
    def handler_eval_expr(self, args):

        if(args.get_expr_args()):
            self.log_message(f"{red}Invalid Expression Syntax")
            return
        
        start_ea, end_ea = None,None

        # section/range attributes
        for p_attr in args.p_args:
            p_attr_name = p_attr['arg_name']
            if p_attr_name not in ["section","range"]:
                continue

            p_attr_value = p_attr['arg_value']
            p_attr_op = p_attr['operator']
            p_attr_rel_next = p_attr['relation_next']            

            if p_attr_op != "=":
                self.err(f"{p_attr_name} attributes support only '=' operator")
                return
            
            if p_attr_rel_next != "and" and p_attr_rel_next != None:
                self.err(f"{p_attr_name} attributes support only '&' relation.")
                return

            if p_attr_name == "section":
                start_ea, end_ea = core.get_section_range_by_name(p_attr_value)
                if self.ASS_VALID(start_ea=start_ea, end_ea=end_ea, err="bad section name"):
                    return
                
            elif p_attr_name == "range":
                try:
                    start_ea, end_ea = map(lambda x: int(x, 16), p_attr_value.split("-"))
                except ValueError:
                    self.err("'range' parameters isn't valid, format -> range=0xY-0xZ")
                    return
    
        functions = core.get_functions_by_range(start_ea, end_ea)
        for p_attr in args.p_args:
            p_attr_name = p_attr['arg_name']
            if p_attr_name in ["section","range"]:
                continue
            p_attr_value = cast_from_str(p_attr['arg_value'])
            p_attr_op = p_attr['operator']
            p_attr_rel_next = p_attr['relation_next']

            p_attr_functions = {}

            # Filter by number of parameters
            if p_attr_name == "param":
                if self.decompilation_warn:
                    self.warn("'param' evaluation may force decompilation, which can be slow.")
                    self.decompilation_warn = 0

                for ea in functions:
                    fp_cnt = core.get_function_parameters_count(ea)
                    if operator(p_attr_op, fp_cnt, p_attr_value):
                        p_attr_functions[ea] = functions[ea]

            # Filter by operation constants (e.g., xor_cst, add_cst)
            elif p_attr_name in operation_register_common:
                op_type = operation_register_common[p_attr_name]
                
                for ea in functions:
                    matched_instr = instr_match_op_cst(core.get_instructions_by_function(ea), op_type, p_attr_value, p_attr_op)
                    if matched_instr:
                        idc.set_color(matched_instr, idc.CIC_ITEM, 0x008000) #green
                        self.highlighted_ea.append(matched_instr)
                        p_attr_functions[ea] = functions[ea]

            # Filter by number of blocks
            elif p_attr_name == "block":
                for ea in functions:
                    nb_block = core.get_number_of_blocks(ea)
                    if operator(p_attr_op, nb_block, p_attr_value):
                        p_attr_functions[ea] = functions[ea]

            #unhandler attributes
            else:
                self.warn(f"Extra attributes {p_attr_name} found! Unhandled")

            if p_attr_rel_next == "and":
                functions = {k: functions[k] for k in functions if k in p_attr_functions}

            elif p_attr_rel_next == "or":
                functions = functions.copy()
                functions.update(p_attr_functions)

            elif p_attr_rel_next == None:
                functions = p_attr_functions
        
        
        functions_list = []
        for ea in functions:
            functions_list.append([ea, functions[ea]])

        c = results.ResultFunction("Expression results", functions_list)
        _ = c.show()

        self.log_message(f"{green} Evaluation : OK | {len(functions_list)} results")
        self.log_message("")
        