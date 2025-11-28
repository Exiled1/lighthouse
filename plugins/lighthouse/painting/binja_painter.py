import logging

import binaryninja
from binaryninja import HighlightStandardColor
from binaryninja.highlight import HighlightColor
from binaryninja.renderlayer import RenderLayer 
from binaryninja import mainthread

from lighthouse.painting import DatabasePainter
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Painting.Binja")

#------------------------------------------------------------------------------
# Binary Ninja Coverage Render Layer
#------------------------------------------------------------------------------

class BinjaCoverageRenderLayer(RenderLayer):
    """
    Render layer for applying Lighthouse coverage highlighting.
    """
    
    director = None
    palette = None
    name = "Lighthouse Coverage" 

    def __init__(self):
        super(BinjaCoverageRenderLayer, self).__init__()
        
    def apply_to_block(self, block, lines):
        """
        Applies coverage highlighting to the lines of a basic block.
        """
        
        if not BinjaCoverageRenderLayer.director or not BinjaCoverageRenderLayer.palette:
            return lines

        db_coverage = BinjaCoverageRenderLayer.director.coverage
        db_metadata = BinjaCoverageRenderLayer.director.metadata
        node_address = block.start
        
        node_metadata = db_metadata.nodes.get(node_address, None)
        node_coverage = db_coverage.nodes.get(node_address, None)
        
        if not (node_coverage and node_metadata):
            return lines

        r, g, b, _ = BinjaCoverageRenderLayer.palette.coverage_paint.getRgb()
        color = HighlightColor(red=r, green=g, blue=b)
        
        covered_instructions = set(node_coverage.executed_instructions.keys())

        for line in lines:
            if line.addr in covered_instructions:
                line.highlight = color
                
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
    # Paint Primitives (simplified to refresh UI)
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
        
        FIXED: Using Function.request_disassembly_redraw() to signal the visual 
        change. This function is often available in Binary Ninja versions that 
        support the Render Layer API.
        """
        bv = disassembler[self.lctx].bv
        
        def update_functions():
            # This logic executes on the main thread
            for func in bv.functions:
                # Attempt the redraw function that is most likely to exist for UI changes.
                if hasattr(func, 'request_disassembly_redraw'):
                    func.request_disassembly_redraw()
                
        # Execute the redraw loop on the main UI thread
        mainthread.execute_on_main_thread(update_functions)

    def _cancel_action(self, job):
        pass