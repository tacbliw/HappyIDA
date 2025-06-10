from __future__ import division
from __future__ import print_function
from struct import unpack
import idaapi
import idautils
import idc
import ida_hexrays
import ida_typeinf
import ida_kernwin
import ida_lines

from PyQt5.QtWidgets import QApplication

ACTION_DOEDIT = "happyida:doedittype"
ACTION_HX_COPYNAME = "happyida:hx_copyname"
ACTION_HX_PASTENAME = "happyida:hx_pastename"
ACTION_HX_COPYTYPE = "happyida:hx_copytype"
ACTION_HX_PASTETYPE = "happyida:hx_pastetype"
ACTION_HX_EDITTYPE = "happyida:hx_edittype"

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def get_clip_text():
    return QApplication.clipboard().text()

def get_func_params(x):
    tinfo = x.type
    func_data = idaapi.func_type_data_t()

    if tinfo.is_funcptr():
        func_type = tinfo.get_pointed_object()
    elif tinfo.is_func():
        func_type = tinfo
    else:
        return None

    assert(func_type.is_func())
    func_type.get_func_details(func_data)

    return func_data

def tag_text(text, tag):
    # address tagging doesn't have COLOR_OFF pair
    FMT = '%c%c%' + '0%dX' % ida_lines.COLOR_ADDR_SIZE + '%s'
    return FMT % (ida_lines.COLOR_ON, ida_lines.COLOR_ADDR, tag, text)

def add_parameter_labels(cf):
    ci = ida_hexrays.ctree_item_t()
    ccode = cf.get_pseudocode()
    target = {}
    for line_idx in range(cf.hdrlines, len(ccode)):
        sl = ccode[line_idx]
        for char_idx in range(len(sl.line)):
            if cf.get_line_item(sl.line, char_idx, True, None, ci, None):
                if ci.it.is_expr() and ci.e.op == ida_hexrays.cot_call:
                    if ci.e.x.op == ida_hexrays.cot_helper:
                        #TODO: build known helper dictionary
                        pass
                    else:
                        args = get_func_params(ci.e.x)
                        if not args:
                            continue

                        for a, arg in zip(ci.e.a, args):
                            name = arg.name
                            ty = arg.type
                            # filter same name cases
                            # TODO: add support to hide tag if A: B->A ? (should filter A: [*&]B->A cases / or not? no sense to do that actually...)
                            if a.dstr() == name:
                                continue

                            idx = a.index
                            tag = a.print1(None)
                            target[tag] = (idx, name)
        for item in list(target.keys()):
            if item in sl.line:
                (index, name) = target.pop(item)
                if name == '':
                    name = "unk"
                label = ida_lines.COLSTR(name, ida_lines.SCOLOR_HIDNAME)
                tagged = tag_text(label, index)
                sl.line = sl.line.replace(item, tagged + ": " + item)

class HexRaysHooks(ida_hexrays.Hexrays_Hooks):
    def func_printed(self, cfunc):
        add_parameter_labels(cfunc)
        return 0

class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_DOEDIT:
            print("do edit!")
            ida_kernwin.open_loctypes_window(g_ordinal)
            idautils.ProcessUiActions("TilEditType")
        else:
            return 0

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

g_ordinal = 0
class hexrays_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hexrays actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
        self.ret_type = {}

    def activate(self, ctx):
        if self.action == ACTION_HX_COPYNAME:
            self.copy_name_to_clipboard()
        elif self.action == ACTION_HX_PASTENAME:
            self.paste_name(ctx)
        elif self.action == ACTION_HX_COPYTYPE:
            self.copy_type(ctx)
        elif self.action == ACTION_HX_PASTETYPE:
            self.paste_type(ctx)
        elif self.action == ACTION_HX_EDITTYPE:
            self.edit_type(ctx)
        else:
            return 0
        return 1

    def copy_name_to_clipboard(self):
        highlight = idaapi.get_highlight(idaapi.get_current_viewer())
        name = highlight[0] if highlight else None
        if name:
            copy_to_clip(name)
            print(f"{name} has been copied to clipboard")

    def paste_name(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)

        item = vdui.item
        if item.is_citem() and item.it.is_expr():
            new_name = get_clip_text()
            if not new_name:
                print("Clipboard is empty or could not read clipboard.")
                return 0
            self.rename_item(vdui, item, new_name)
        elif item.citype == ida_hexrays.VDI_FUNC:
            func_addr = item.f.entry_ea
            new_name = get_clip_text()
            idaapi.set_name(func_addr, new_name, idaapi.SN_NOWARN)
            vdui.refresh_view(True)
        elif item.l:
            lvar = item.l
            new_name = get_clip_text()
            if vdui.rename_lvar(lvar, new_name, True):
                print(f"Renamed variable to '{new_name}'")
            else:
                print(f"Failed to rename variable to '{new_name}'")
                vdui.ui_rename_lvar(lvar)
            vdui.refresh_ctext(True)
        else:
            print("Currently unsupported")

    def rename_item(self, vdui, item, new_name):
        if item.e.v is not None:
            lvar = item.e.v.getv()
            if vdui.rename_lvar(lvar, new_name, True):
                print(f"Renamed variable to '{new_name}'")
            else:
                print(f"Failed to rename variable to '{new_name}'")
                vdui.ui_rename_lvar(lvar)
        elif item.e.obj_ea != idaapi.BADADDR:
            idc.set_name(item.e.obj_ea, new_name, idc.SN_NOWARN)
            print(f"Renamed name of {hex(item.e.obj_ea)} to '{new_name}'")
        elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
            self.rename_member(item, new_name)
        else:
            print("No variable under cursor or not a valid lvar item.")
        vdui.refresh_ctext()

    def rename_member(self, item, new_name):
        # Prepare buffers
        udm_data = idaapi.udm_t()
        parent_tinfo = idaapi.tinfo_t()
        # Assuming item, udm_data, and parent_tinfo are defined
        index = item.get_udm(udm_data, parent_tinfo, None)

        if index != -1:
            # Print information
           self.rename_member_name(parent_tinfo, udm_data.offset, new_name)
        else:
            print("Failed to get UDM information.")

    def copy_type(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        item = vdui.item
        if item.is_citem() and item.it.is_expr():
            if item.e.v is not None:
                lvar = item.e.v.getv()
                type_name = lvar.tif.dstr()
                copy_to_clip(type_name)
                print(f"{type_name} has been copied to clipboard")
            elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                udm_data = idaapi.udm_t()
                parent_tinfo = idaapi.tinfo_t()
                item.get_udm(udm_data, parent_tinfo, None)
                type_name = udm_data.type.dstr()
                copy_to_clip(type_name)
                print(f"{type_name} has been copied to clipboard")
            elif item.e.obj_ea != idaapi.BADADDR:
                type_name = idc.get_type(item.e.obj_ea)
                copy_to_clip(type_name)
                print(f"{type_name} has been copied to clipboard")
            else:
                print("Nothing")
        else:
            print("No variable under cursor or not a valid lvar item.")

    def paste_type(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)

        item = vdui.item
        if item.is_citem() and item.it.is_expr():
            if item.e.v is not None:
                lvar = item.e.v.getv()
                self.assign_type_to_lvar(vdui, lvar)
            elif item.e.obj_ea != idaapi.BADADDR:
                type_name = get_clip_text()
                idc.SetType(item.e.obj_ea, type_name + " ;")
                print(f"{type_name} has been assigned to variable")
                vdui.refresh_view(True)
            elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                type_name = get_clip_text()
                udm_data = idaapi.udm_t()
                parent_tinfo = idaapi.tinfo_t()
                item.get_udm(udm_data, parent_tinfo, None)
                # Get the udm array
                struct_type_data = idaapi.udt_type_data_t()
                if not parent_tinfo.get_udt_details(struct_type_data):
                    print("Failed to get UDT details")
                    return None
                # find the udm index in udm array
                # TODO: item.get_udm actually return the index
                index = 0
                for member in struct_type_data:
                    if member.offset == udm_data.offset:
                        break
                    index += 1
                # Create new type
                type_name = get_clip_text()
                new_tif = idaapi.tinfo_t()
                if not new_tif.get_named_type(ida_typeinf.get_idati(), type_name):
                    ida_typeinf.parse_decl(new_tif, ida_typeinf.get_idati(), type_name + " ;",0)
                parent_tinfo.set_udm_type(index, new_tif)
                print(f"{type_name} has been assigned to variable")
            else:
                print("Nothing")
        else:
            print("No variable under cursor or not a valid lvar item.")
        pass

    def assign_type_to_lvar(self, vdui, lvar):
        new_tif = idaapi.tinfo_t()
        if not new_tif.get_named_type(ida_typeinf.get_idati(), get_clip_text()):
            print(get_clip_text() + " ;")
            print(ida_typeinf.parse_decl(new_tif, ida_typeinf.get_idati(), get_clip_text() + " ;",0))
            print(new_tif)

        lsi = ida_hexrays.lvar_saved_info_t()
        lsi.ll = lvar
        lsi.type = new_tif
        if not ida_hexrays.modify_user_lvar_info(vdui.cfunc.entry_ea, ida_hexrays.MLI_TYPE, lsi):
            print(f"Could not modify lvar type for {lvar.name}")
            return False
        print(f"{new_tif} has been assigned to variable")
        vdui.refresh_view(True)

    def edit_type(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)

        item = vdui.item
        if item.is_citem() and item.it.is_expr():
            if item.e.v is not None:
                t = item.e.v.getv().type()
                self._edit_type(t)
            elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                    udm_data = idaapi.udm_t()
                    parent_tinfo = idaapi.tinfo_t()
                    item.get_udm(udm_data, parent_tinfo, None)
                    self._edit_type(udm_data.type)
            elif item.e.obj_ea != idaapi.BADADDR:
                type_name = idc.get_type(item.e.obj_ea)
                new_tif = idaapi.tinfo_t()
                if not new_tif.get_named_type(ida_typeinf.get_idati(), type_name):
                    ida_typeinf.parse_decl(new_tif, ida_typeinf.get_idati(), type_name + " ;",0)
                self._edit_type(new_tif)
        else:
            print("No variable under cursor or not a valid lvar item.")

    def _edit_type(self, t):
        while t.is_ptr_or_array():
            t.remove_ptr_or_array()
        ordinal = t.get_ordinal()
        if ordinal != 0:
            """
            We have to put the following line into a new action
            not sure why, because if we run the following script in script window, it's fine
            but if we put them here, we'll land on other structure then edit the wrong type.
            ```
            ida_kernwin.open_loctypes_window(ordinal)
            idautils.ProcessUiActions("TilEditType")
            ```
            """
            global g_ordinal
            g_ordinal = ordinal
            idautils.ProcessUiActions(ACTION_DOEDIT)

    def update(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        return idaapi.AST_ENABLE_FOR_WIDGET if vdui else idaapi.AST_DISABLE_FOR_WIDGET

    def rename_member_name(self, tinfo, offset, new_name):
        # Check if the type is a structure
        if not tinfo.is_struct():
            print("Provided type is not a structure")
            return None

        # Get the structure ID
        struct_type_data = idaapi.udt_type_data_t()

        if not tinfo.get_udt_details(struct_type_data):
            print("Failed to get UDT details")
            return None

        # Iterate through the members to find the one at the specified offset
        count = 0
        for member in struct_type_data:
            if member.offset == offset:
                print(idc.get_member_name(tinfo.get_ordinal(), member.offset))
                print(member.name, member.can_rename())
                if member.can_rename():
                    member.name = new_name
                    if tinfo.rename_udm(count, new_name):
                        print(f"Member at offset {offset} renamed to {new_name}")
                        return new_name
                    else:
                        print(f"Failed to rename member at offset {offset}")
                        return None
            count += 1
        print("No member found at the specified offset")
        return None

class HappyIDA_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "HappyIDA"
    help = ""
    wanted_name = "HappyIDA"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

        # Register do edit
        edit = idaapi.action_desc_t(ACTION_DOEDIT, "Really do edit", menu_action_handler_t(ACTION_DOEDIT), None, None, 0x10)
        idaapi.register_action(edit)
        self.registered_actions.append(edit.name)

        if idaapi.init_hexrays_plugin():
            # Add hexrays ui callback
            hx_actions = (
                idaapi.action_desc_t(ACTION_HX_COPYNAME, "Copy name", hexrays_action_handler_t(ACTION_HX_COPYNAME), "c"),
                idaapi.action_desc_t(ACTION_HX_PASTENAME, "Paste name", hexrays_action_handler_t(ACTION_HX_PASTENAME), "V"),
                idaapi.action_desc_t(ACTION_HX_COPYTYPE, "Copy type", hexrays_action_handler_t(ACTION_HX_COPYTYPE), "Ctrl-Alt-C"),
                idaapi.action_desc_t(ACTION_HX_PASTETYPE, "Copy type", hexrays_action_handler_t(ACTION_HX_PASTETYPE), "Ctrl-Alt-V"),
                idaapi.action_desc_t(ACTION_HX_EDITTYPE, "Edit type", hexrays_action_handler_t(ACTION_HX_EDITTYPE), "e"),
            )
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hx_actions.append(action.name)

            # Register hexrays hook
            self.hr_hooks = HexRaysHooks()
            self.hr_hooks.hook()

            self.hexrays_inited = True

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)

        if self.hexrays_inited:
            # Unregister hexrays actions
            for action in self.registered_hx_actions:
                idaapi.unregister_action(action)

            # Unregister hexrays hook
            self.hr_hooks.unhook()

            # TODO: what is this?
            idaapi.term_hexrays_plugin()

def PLUGIN_ENTRY():
    return HappyIDA_t()
