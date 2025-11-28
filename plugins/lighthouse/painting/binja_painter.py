import logging

import binaryninja
from binaryninja import HighlightStandardColor
from binaryninja.highlight import HighlightColor
from binaryninja.renderlayer import RenderLayer 
from binaryninja.enums import RenderLayerDefaultEnableState
from binaryninja import mainthread
from typing import TYPE_CHECKING
from lighthouse.util.log import lmsg

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
    # Core Coloring Logic (Helper)
    #--------------------------------------------------------------------------

    def _get_coverage_key(self, block):
        """
        Retrieves the correct native address to use as the lookup key for Lighthouse coverage.
        """
        if block.is_il and hasattr(block, 'source_block') and block.source_block is not None:
            # For ILs, the coverage key is the start address of the underlying native block.
            return block.source_block.start
        
        # For Disassembly blocks, or if source_block is missing/unreliable, use block.start.
        return block.start

    def apply_to_disassembly_block(self, block: 'BasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_low_level_il_block(self, block: 'LowLevelILBasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_medium_level_il_block(self, block: 'MediumLevelILBasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_high_level_il_block(self, block: 'HighLevelILBasicBlock', lines):
        return self._apply_coverage_highlighting(block, lines)

    def _apply_coverage_highlighting(self, block, lines):
        """
        Applies coverage highlighting to the lines of a given block.
        """
        
        native_block_addr = self._get_coverage_key(block)
        is_il_block = block.is_il
        
        # lmsg(f"Lighthouse RenderLayer: START block {native_block_addr:#x} (IL: {is_il_block}, Type: {type(block)}, Lines: {len(lines)})")

        if not self.director or not self.palette:
            return lines

        db_coverage = self.director.coverage
        db_metadata = self.director.metadata

        # Use the calculated native address key for metadata/coverage lookup.
        node_metadata = db_metadata.nodes.get(native_block_addr, None)
        node_coverage = db_coverage.nodes.get(native_block_addr, None)
        
        if not (node_coverage and node_metadata):
            # lmsg(f"Lighthouse RenderLayer: END block {native_block_addr:#x} (No Coverage/Metadata found)")
            return lines

        r, g, b, _ = self.palette.coverage_paint.getRgb()
        color = HighlightColor(red=r, green=g, blue=b)
        
        covered_instructions = set(node_coverage.executed_instructions.keys())
        lines_processed = 0
        lines_highlighted = 0

        # Apply line highlighting for all blocks (Disassembly + ILs)
        for line in lines:
            lines_processed += 1
            # Using getattr for defensive access to the instruction address
            address = getattr(line, 'address', None)

            if address is not None:
                 is_covered = address in covered_instructions
                 
                 if is_il_block:
                     # Log the IL lines only for debugging visibility
                     tokens = getattr(line, 'tokens', None)
                     text_summary = "".join(t.text for t in tokens) if tokens else 'N/A'
                     # lmsg(f"  IL Line {lines_processed}: Addr {address:#x}, Covered: {is_covered}, Text: '{text_summary[:50]}'")

            # Skip if address is None (non-instruction line) or not covered.
            if address is None or address not in covered_instructions:
                continue

            # Apply highlight
            line.highlight = color
            lines_highlighted += 1
            
        #lmsg(f"Lighthouse RenderLayer: END block {native_block_addr:#x} (Processed: {lines_processed}, Highlighted: {lines_highlighted})")
        return lines

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