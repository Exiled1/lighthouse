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
    Render layer for applying Lighthouse coverage highlighting.
    """
    
    # Static properties to be set externally by the BinjaPainter
    director = None
    palette = None

    # Layer Name (for registration and UI menu)
    name = "Lighthouse Coverage" 

    # Explicitly set to enable by default and show in the View Options menu
    default_enable_state = RenderLayerDefaultEnableState.EnabledByDefaultRenderLayerDefaultEnableState

    def __init__(self):
        # Call base constructor without arguments
        super(BinjaCoverageRenderLayer, self).__init__()
        
    def apply_to_block(self, block, lines):
        """
        Applies coverage highlighting to the lines of a basic block.
        """
        
        # Check if context data is available
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
            address = getattr(line, 'address', None)

            # Address is empty.
            if address is None or address not in covered_instructions:
                continue

            # Apply highlight
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

        # Register the Render Layer once per BN session
        if BinjaPainter._coverage_render_layer is None:
            BinjaCoverageRenderLayer.register()
            BinjaPainter._coverage_render_layer = True
        
        # Update the static context properties for the new view/session
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
        Must be executed on the main thread to interact with the UI.
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