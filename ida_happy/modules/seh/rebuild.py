import idaapi
import ida_hexrays
import ida_kernwin
import ida_tryblks
import ida_range
import re

from ida_happy.miscutils import info, error

class HexraysRebuildSEHHook(ida_hexrays.Hexrays_Hooks):
    """rebuild the missing SEH try except statements"""
    def __init__(self):
        super().__init__()
        self.seh_list = []
        self.banned_set = set()
        self.notify_user = False

    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        self.seh_list = []
        self.notify_user = False
        self.gather_seh_info(mba, fc, reachable_blocks)
        return 0

    def microcode(self, mba):
        self.insert_catch_block(mba)
        return 0

    def maturity(self, cfunc, maturity):
        if maturity == idaapi.CMAT_FINAL:
            self.mutate_ctree(cfunc)
        return 0

    def func_printed(self, cfunc):
        self.annotate_seh(cfunc)

        if self.notify_user:
            ida_kernwin.warning('Unable to correctly decompile some try blocks, press "F5" again to resolve it.')
        return 0

    def gather_seh_info(self, mba, fc, reachable_blocks):
        func = idaapi.get_func(mba.entry_ea)

        tbks = ida_tryblks.tryblks_t()
        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        blk_idx_map = {}

        for i in range(fc.size()):
            blk_idx_map[fc[i].start_ea] = i

        for idx, tryblock in enumerate(tbks):
            # skip block 0 (it covers the function itself)
            # skip cpp seh
            if not idx or not tryblock.is_seh():
                continue

            # print(f'try block #{idx}')
            # TODO: should consider nested SEH case
            # TODO: could contain multiple ranges (nested case?), should check if len > 1
            # finally block?
            rge = tryblock[0]
            try_start = rge.start_ea
            try_end = rge.end_ea

            if try_start in self.banned_set:
                info(f'ignore try block @ {hex(try_start)}')
                continue

            eh_start_list = []
            for eh in tryblock.seh():
                # since some unreachable catch blocks are never included in the microcode block list,
                # we have to restore all blocks reachable from the catch block in bitmap

                # initialize the list with catch block index
                blocks = [blk_idx_map[eh.start_ea]]

                # traverse all blocks from catch block
                while len(blocks):
                    block_idx = blocks.pop()
                    if not reachable_blocks.has(block_idx):
                        info(f'restore unreferenced block #{block_idx}')
                        reachable_blocks.add(block_idx)
                        # push all successors into list
                        for i in range(fc.nsucc(block_idx)):
                            blocks.append(fc.succ(block_idx, i))

                eh_start_list.append(eh.start_ea)

            # print(f'range: [{hex(try_start)}, {hex(try_end)})')
            # print(f'handler: {[hex(i) for i in eh_start_list]}')

            # NOTE: currently support only one catch block
            # also, it looks like msvc only accept one __except block?
            self.seh_list.append((try_start, try_end, eh_start_list[0]))

    def insert_catch_block(self, mba: ida_hexrays.mba_t):
        func = idaapi.get_func(mba.entry_ea)
        tbks = ida_tryblks.tryblks_t()

        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        def traverse_blocks(blocks):
            # always skip entry block and exit block
            cur = blocks.nextb
            while cur.start != idaapi.BADADDR:
                yield cur
                cur = cur.nextb

        bb_start_map = {}
        for block in traverse_blocks(mba.blocks):
            bb_start_map[block.start] = block

        # add multiple new block
        # insert jz to reference catch block in decompiler generated ctree
        for try_start, try_end, eh_start in self.seh_list:
            try_bk = bb_start_map[try_start]
            eh_bk = bb_start_map[eh_start]

            # this will auto update all the block numbers
            blk = mba.insert_block(try_bk.serial)
            blk.start = try_start
            blk.end = try_start + 1

            # jz [0x41414141], 0x69, @eh_idx
            l = ida_hexrays.mop_t()
            r = ida_hexrays.mop_t()
            d = ida_hexrays.mop_t()

            # 1 byte global variable @ 0x41414141
            l.t = idaapi.mop_v
            l.g = 0x41414141
            l.size = 1
            # 1 byte constant 0x69
            r.make_number(0, 1)
            # reference to block #eh_bk
            d.make_blkref(eh_bk.serial)

            # map to try_start to ease the search during next stage
            insn = ida_hexrays.minsn_t(try_start)
            insn.opcode = idaapi.m_jnz
            insn.l = l
            insn.r = r
            insn.d = d
            blk.insert_into_block(insn, blk.tail)

    def mutate_ctree(self, cfunc):
        # transform:
        # ```
        # if (ADDR[0x41414141]) { ... except block }
        # ...
        # { ... try block }
        # ```
        # into:
        # ```
        # { ... try block }
        # { ... except block }
        # ```
        # TODO: control flow can actually jump between different try block region,
        # so each block in the try block should be handled differently.
        # currently I have no idea to resolve this...
        body = cfunc.body
        insn_map = {}
        # find_closest_addr and find_parent_of will re-iterate the ctree,
        # so it's safe to mutate the tree in the loop

        def block_iter(block, idx):
            cur = block.begin()
            while idx:
                next(cur)
                idx -= 1
            return cur

        # the first search will give us the catch block, which is inserted at the same address
        # but precedes the try block in block order
        for try_start, try_end, eh_start in self.seh_list:
            it = body.find_closest_addr(try_start)
            while it:
                if not it.is_expr() \
                   and it.op == idaapi.cit_if \
                   and it.cinsn.cif.expr.op == idaapi.cot_obj \
                   and it.cinsn.cif.expr.obj_ea == 0x41414141:
                    break
                it = body.find_parent_of(it)
            else:
                self.notify_user = True
                self.banned_set.add(try_start)
                error(f'Failed to find valid catch block @ {hex(try_start)}')
                continue

            cur_insn = it.cinsn
            cif = cur_insn.cif

            # transform: if (...) { A... } else { B... }
            # into: if (...) { A... } B...
            # TODO: we *should* consider the inverted case (if (![0x41414141]){...})
            # if else branch exists, move the contents (contains try, and maybe other blocks) out of the if block
            if cif.ielse:
                else_block = cif.ielse.cblock

                pi = body.find_parent_of(it).cinsn
                assert(pi.op == ida_hexrays.cit_block)

                blk_iter = pi.cblock.begin()
                while blk_iter != pi.cblock.end():
                    if blk_iter.cur == cur_insn:
                        break
                    next(blk_iter)

                next(blk_iter)
                # TODO: need to handle label_num
                while else_block.begin() != else_block.end():
                    insn = ida_hexrays.cinsn_t()
                    insn.swap(else_block.begin().cur)
                    else_block.erase(else_block.begin())
                    pi.cblock.insert(blk_iter, insn)

            # swap out the insn(cblock_t) from if.then to move it up by one level
            insn = ida_hexrays.cinsn_t()
            insn.swap(cif.ithen)

            # NOTE: important step here, otherwise pop INTERR 50728
            if insn.label_num != -1 and cur_insn.label_num != -1:
                # TODO: eventually need to fix this
                pass
            elif cur_insn.label_num != -1:
                insn.label_num = cur_insn.label_num

            cur_insn.swap(insn)
            cur_insn.ea = eh_start

            # NOTE: we cannot set ea to arbitrary insn: cif_t requires it.ea == it.cif.expr.ea
            # workaround for `if ([0x41414141]) break;`
            # cur_insn.cblock[0].ea = eh_start # causing INTERR 50683

            # TODO: need to find another way to handle break
            # if cur_insn.cblock[0].op == idaapi.cit_break:
            #     insn = ida_hexrays.cinsn_t()
            #     insn.op = ida_hexrays.cit_goto
            #     insn.ea = eh_start
            #     insn.cgoto = ida_hexrays.cgoto_t()
            #     insn.cgoto.label_num = 6666
            #     cur_insn.swap(insn)
            #     it = body.find_closest_addr(eh_start)
            #     while it.is_expr():
            #         it = body.find_parent_of(it)
            #     it.label_num = 6666

            insn_map[try_start] = cur_insn

        # the second search will yield the actual try block (currently just an expr),
        # since we just delete the preceding if statement
        for try_start, try_end, eh_start in self.seh_list:
            # TODO: should remove this after the issue resolved
            if try_start not in insn_map:
                continue

            # find the start expr of the new try block
            it = body.find_closest_addr(try_start)
            while it.is_expr():
                it = body.find_parent_of(it)

            cur_insn = it.cinsn
            pi = body.find_parent_of(it).cinsn

            # sanity check
            assert(pi.op == ida_hexrays.cit_block)

            start_idx = 0
            while pi.cblock[start_idx] != cur_insn:
                start_idx += 1

            for end_idx in range(start_idx, pi.cblock.size()):
                if pi.cblock[end_idx].ea >= try_end:
                    break
            else:
                end_idx += 1

            try_block = ida_hexrays.cblock_t()
            try_insn = ida_hexrays.cinsn_t()
            try_insn.op = idaapi.cit_block
            try_insn.cblock = try_block
            # NOTE: important step here, otherwise pop INTERR 50681
            # plugins/hexrays_sdk/verifier/cverify.cpp
            try_insn.ea = try_start

            for idx in range(start_idx, end_idx):
                # NOTE: we cannot do this because the erase operation will always free the object
                # instead, using swap to take out the insn obj
                # try_block.push_back(pi.cblock[idx])
                new_insn = ida_hexrays.cinsn_t()
                new_insn.swap(pi.cblock[idx])
                try_block.push_back(new_insn)

            for _ in range(end_idx - start_idx):
                # no way to duplicate a iterator...
                it = block_iter(pi.cblock, start_idx)
                pi.cblock.erase(it)

            it = block_iter(pi.cblock, start_idx)
            pi.cblock.insert(it, try_insn)

            # move catch block below the try block (swap it out first)
            catch_insn = insn_map[try_start]
            cpi = body.find_parent_of(catch_insn).cinsn
            assert(cpi.op == ida_hexrays.cit_block)
            blk_iter = cpi.cblock.begin()
            while blk_iter != cpi.cblock.end():
                if blk_iter.cur == catch_insn:
                    break
                next(blk_iter)
            else:
                raise Exception('Failed to get previous block iterator')

            catch_insn = ida_hexrays.cinsn_t()
            catch_insn.swap(blk_iter.cur)
            cpi.cblock.erase(blk_iter)

            pi.cblock.insert(it, catch_insn)

            # NOTE: the type of splice binding is flawed... (qlist< cinsn_t >::iterator v.s. cinsn_list_t_iterator)
            # cblock.splice(cblock, pi.cblock, start_ptr, end_ptr)
            del insn_map[try_start]

        if insn_map:
            error('Failed to find all try blocks')

    def annotate_seh(self, cfunc):
        ccode = cfunc.get_pseudocode()
        try_set = set(try_start for try_start, _, _ in self.seh_list)
        eh_set = set(eh_start for _, _, eh_start in self.seh_list)

        for i in range(len(cfunc.treeitems)):
            insn = cfunc.treeitems[i]
            if insn.op == ida_hexrays.cit_block and insn.ea in try_set:
                try_insn = cfunc.treeitems[i].cinsn
                x, y = cfunc.find_item_coords(try_insn)
                ccode[y].line = ccode[y].line.replace('{', '__try {')

            elif insn.op == ida_hexrays.cit_block and insn.ea in eh_set:
                try_insn = cfunc.treeitems[i].cinsn
                x, y = cfunc.find_item_coords(try_insn)
                if '{' in ccode[y].line:
                    ccode[y].line = ccode[y].line.replace('{', '__except(...) {')
                else:
                    # workaround to handle oneline return & break (maybe continue?)
                    # since it will not contain the `{ ... }` syntax
                    matched = re.match('(.*)(return|break|continue)(.*)', ccode[y].line)
                    if not matched:
                        error('failed to find exception code block')
                        continue
                    ccode[y].line = matched[1] + '__except(...) { ' + matched[2] + matched[3] + ' }'
