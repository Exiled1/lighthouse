import logging

import binaryninja
from binaryninja import HighlightStandardColor
from binaryninja.highlight import HighlightColor
from binaryninja.renderlayer import RenderLayer

from lighthouse.painting import DatabasePainter
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Painting.Binja")

#------------------------------------------------------------------------------
# Binary Ninja Coverage Render Layer
#------------------------------------------------------------------------------

class BinjaCoverageRenderLayer(RenderLayer):
    """
    Render layer for applying Lighthouse coverage highlighting.
    
    This layer dynamically applies highlight colors to disassembly lines 
    based on the current coverage data held by the Director.
    """
    
    # Static properties to be set externally by the BinjaPainter
    director = None
    palette = None

    # Set the layer name as a class attribute.
    name = "Lighthouse Coverage" 

    # Remove the 'name' argument and call super().__init__ without arguments.
    def __init__(self):
        super(BinjaCoverageRenderLayer, self).__init__()
        
    def apply_to_block(self, block, lines):
        """
        Applies coverage highlighting to the lines of a basic block.
        """
        
        # If the director or palette is not set, skip painting
        if not BinjaCoverageRenderLayer.director or not BinjaCoverageRenderLayer.palette:
            return lines

        db_coverage = BinjaCoverageRenderLayer.director.coverage
        db_metadata = BinjaCoverageRenderLayer.director.metadata
        node_address = block.start
        
        node_metadata = db_metadata.nodes.get(node_address, None)
        node_coverage = db_coverage.nodes.get(node_address, None)
        
        # If no coverage or metadata for this block, return unhighlighted lines
        if not (node_coverage and node_metadata):
            return lines

        # Get the coverage highlight color
        r, g, b, _ = BinjaCoverageRenderLayer.palette.coverage_paint.getRgb()
        color = HighlightColor(red=r, green=g, blue=b)
        
        # Collect all covered instruction addresses within this basic block
        covered_instructions = set(node_coverage.executed_instructions.keys())

        # Apply the highlight color to each covered instruction line
        for line in lines:
            # DisassemblyTextLine.addr is the address of the instruction
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

    # Static variable now acts as a registration flag (True if registered)
    _coverage_render_layer = None

    def __init__(self, lctx, director, palette):
        super(BinjaPainter, self).__init__(lctx, director, palette)

        # Initialize and register the Render Layer once globally
        if BinjaPainter._coverage_render_layer is None:
            BinjaCoverageRenderLayer.register()
            
            # Mark as registered
            BinjaPainter._coverage_render_layer = True
        
        # Update the shared layer properties for the current context
        BinjaCoverageRenderLayer.director = director
        BinjaCoverageRenderLayer.palette = palette


    #--------------------------------------------------------------------------
    # Paint Primitives (simplified to refresh UI)
    #--------------------------------------------------------------------------

    def _paint_instructions(self, instructions):
        # The Render Layer handles drawing. Simply refresh.
        self._refresh_ui()
        self._action_complete.set()

    def _clear_instructions(self, instructions):
        # The Render Layer handles clearing. Simply refresh.
        self._refresh_ui()
        self._painted_partial -= set(instructions)
        self._painted_instructions -= set(instructions)
        self._action_complete.set()

    def _partial_paint(self, bv, instructions, color):
        # Partial paint is handled by the Render Layer logic. Simply refresh.
        self._refresh_ui()
        self._painted_partial |= set(instructions)
        self._painted_instructions |= set(instructions)

    def _paint_nodes(self, node_addresses):
        # Nodes are painted by the Render Layer. Simply refresh.
        self._painted_nodes |= set(node_addresses)
        self._refresh_ui()
        self._action_complete.set()

    def _clear_nodes(self, node_addresses):
        # Nodes are cleared by the Render Layer. Simply refresh.
        self._painted_nodes -= set(node_addresses)
        self._refresh_ui()
        self._action_complete.set()

    def _refresh_ui(self):
        """
        Triggers a redraw of all relevant views to engage the Render Layer.
        """
        bv = disassembler[self.lctx].bv
        # This is the new API call to refresh Render Layers
        bv.recalculate_render_layer()

    def _cancel_action(self, job):
        pass