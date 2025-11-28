import logging

import binaryninja
from binaryninja import HighlightStandardColor
from binaryninja.highlight import HighlightColor
from binaryninja.renderlayer import RenderLayer 
from binaryninja.enums import RenderLayerDefaultEnableState
from binaryninja import mainthread
from typing import TYPE_CHECKING
from lighthouse.util.log import lmsg # Using lmsg for debugging visibility

from lighthouse.painting import DatabasePainter
from lighthouse.util.disassembler import disassembler

if TYPE_CHECKING:
    from binaryninja import BasicBlock, LowLevelILBasicBlock, MediumLevelILBasicBlock, HighLevelILBasicBlock

#------------------------------------------------------------------------------
# Binary Ninja Coverage Render Layer
#------------------------------------------------------------------------------

class BinjaCoverageRenderLayer(RenderLayer):
    """
    Render layer for applying Lighthouse coverage highlighting across all view types.
    """
    
    director = None
    palette = None

    name = "Lighthouse Coverage" 
    default_enable_state = RenderLayerDefaultEnableState.EnabledByDefaultRenderLayerDefaultEnableState

    def __init__(self):
        super(BinjaCoverageRenderLayer, self).__init__()

    #--------------------------------------------------------------------------
    # Core Logic
    #--------------------------------------------------------------------------

    def _get_coverage_key(self, block, lines):
        """
        Retrieves the correct native address (Native Basic Block Start) 
        to use as the lookup key for Lighthouse coverage.
        
        FIX: Uses the address of the first line to find the containing Native Basic Block.
        """
        # If it's a native block, use its start address directly.
        if not block.is_il:
            return block.start

        # --- IL Block Logic: Resolve to Native Basic Block using the line address anchor ---
        
        # Get the address of the first instruction represented by this IL block.
        if not lines or not hasattr(lines[0], 'address'):
            return block.function.start if block.function else block.start

        native_instr_addr = getattr(lines[0], 'address', None)
        
        if native_instr_addr is None:
            return block.function.start if block.function else block.start
        
        # Use the native instruction address to find the containing Native Basic Block.
        native_bb = block.function.get_basic_block_at(native_instr_addr)
        
        if native_bb:
            # Yay! Found the native BasicBlock.
            return native_bb.start

        # Fallback to the function's native start address.
        return block.function.start if block.function else block.start


    def _apply_coverage_highlighting(self, block, lines):
        """
        Applies coverage highlighting to the lines of a given block (private helper).
        """
        
        native_block_addr = self._get_coverage_key(block, lines)
        
        if not self.director or not self.palette:
            return lines

        db_coverage = self.director.coverage
        db_metadata = self.director.metadata

        # Use the calculated native address key for metadata/coverage lookup.
        node_metadata = db_metadata.nodes.get(native_block_addr, None)
        node_coverage = db_coverage.nodes.get(native_block_addr, None)
        
        if not (node_coverage and node_metadata):
            return lines

        r, g, b, _ = self.palette.coverage_paint.getRgb()
        color = HighlightColor(red=r, green=g, blue=b)
        
        covered_instructions = set(node_coverage.executed_instructions.keys())

        # Apply line highlighting for all blocks (Disassembly + ILs)
        for line in lines:
            # Using getattr for defensive access to the instruction address
            address = getattr(line, 'address', None)

            # Skip if address is None (non-instruction line) or not covered.
            if address is None or address not in covered_instructions:
                continue

            # Apply highlight
            line.highlight = color
                
        return lines

    #--------------------------------------------------------------------------
    # Explicit Render Layer API Implementations
    #--------------------------------------------------------------------------

    def apply_to_disassembly_block(self, block: 'BasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_low_level_il_block(self, block: 'LowLevelILBasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_medium_level_il_block(self, block: 'MediumLevelILBasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_high_level_il_block(self, block: 'HighLevelILBasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)


#------------------------------------------------------------------------------
# Binary Ninja Painter
#------------------------------------------------------------------------------

class BinjaPainter(DatabasePainter):
    """
    Asynchronous Binary Ninja database painter, now implemented via Render Layers.
    """

    _coverage_render_layer = None

    def __init__(self, lctx, director, palette):
        super(BinjaPainter, self).__init__(lctx, director, palette)

        if BinjaPainter._coverage_render_layer is None:
            BinjaCoverageRenderLayer.register()
            BinjaPainter._coverage_render_layer = True
        
        BinjaCoverageRenderLayer.director = director
        BinjaCoverageRenderLayer.palette = palette


    #--------------------------------------------------------------------------
    # Paint Primitives (converted to refresh UI)
    #--------------------------------------------------------------------------

    def _paint_instructions(self, instructions):
        self._refresh_ui()
        self._action_complete.set()
    def _clear_instructions(self, instructions):
        self._refresh_ui()
        self._painted_partial -= set(instructions)
        self._painted_instructions -= set(instructions)
        self._action_complete.set()
    def _partial_paint(self, bv, instructions, color):
        self._refresh_ui()
        self._painted_partial |= set(instructions)
        self._painted_instructions |= set(instructions)
    def _paint_nodes(self, node_addresses):
        self._painted_nodes |= set(node_addresses)
        self._refresh_ui()
        self._action_complete.set()
    def _clear_nodes(self, node_addresses):
        self._painted_nodes -= set(node_addresses)
        self._refresh_ui()
        self._action_complete.set()


    def _refresh_ui(self):
        """
        Triggers a redraw of all relevant views to engage the Render Layer.
        """
        bv = disassembler[self.lctx].bv
        
        def update_functions():
            for func in bv.functions:
                if hasattr(func, 'request_disassembly_redraw'):
                    func.request_disassembly_redraw()
                elif hasattr(func, 'request_disassembly_update'):
                    func.request_disassembly_update()
                
        mainthread.execute_on_main_thread(update_functions)

    def _cancel_action(self, job):
        pass