import logging

import binaryninja
from binaryninja import HighlightStandardColor
from binaryninja.highlight import HighlightColor
from binaryninja.renderlayer import RenderLayer 
from binaryninja.enums import RenderLayerDefaultEnableState
from binaryninja import mainthread

from lighthouse.painting import DatabasePainter
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Painting.Binja")

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
    # Core Logic (Private Helper)
    #--------------------------------------------------------------------------

    def _apply_coverage_highlighting(self, block, lines):
        """
        Applies coverage highlighting to the lines of a given block (private helper).
        """
        
        if not self.director or not self.palette:
            return lines

        db_coverage = self.director.coverage
        db_metadata = self.director.metadata
        node_address = block.start
        
        node_metadata = db_metadata.nodes.get(node_address, None)
        node_coverage = db_coverage.nodes.get(node_address, None)
        
        if not (node_coverage and node_metadata):
            return lines

        r, g, b, _ = self.palette.coverage_paint.getRgb()
        color = HighlightColor(red=r, green=g, blue=b)
        
        covered_instructions = set(node_coverage.executed_instructions.keys())

        for line in lines:
            address = getattr(line, 'address', None)

            # Skip if address is None (non-instruction line) or not covered.
            if address is None or address not in covered_instructions:
                continue

            # Apply highlight
            line.highlight = color
                
        return lines

    #--------------------------------------------------------------------------
    # Explicit Render Layer API Implementations (Required for ILs)
    #--------------------------------------------------------------------------
    
    def apply_to_disassembly_block(self, block, lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_low_level_il_block(self, block, lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_medium_level_il_block(self, block, lines):
        return self._apply_coverage_highlighting(block, lines)

    def apply_to_high_level_il_block(self, block, lines):
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