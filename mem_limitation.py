from angr import ExplorationTechnique


import angr
from angr.sim_type import SimTypeLength, SimTypeTop
import itertools

import logging
l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)

NO_OOM_MEMSIZE = '__WM_MEMSIZE'
CLAIM_TRIGGERED = '__WM_MEMCLAIM'


######################################
# malloc
######################################


class OOMalloc(angr.SimProcedure):
    def run(self, sim_size):
        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))
        # this function contains logic errors, including not confirming the resulting
        # size is a valid one, but it's not likely to fail either
        # misbehave in the general sense
        actual_val = self.state.heap._conc_alloc_size(sim_size)
        if actual_val > self.state.globals[NO_OOM_MEMSIZE]:
            return 0
        self.state.globals[NO_OOM_MEMSIZE] -= actual_val
        return self.state.heap._malloc(actual_val)

class OOMcalloc(angr.SimProcedure):
    def run(self, sim_nmemb, sim_size):
        self.argument_types = { 0: SimTypeLength(self.state.arch),
                                1: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeArray(SimTypeTop(sim_size), sim_nmemb))
        actual_val = self.state.heap._conc_alloc_size(sim_nmemb * sim_size)
        if actual_val > self.state.globals[NO_OOM_MEMSIZE]:
            return 0
        self.state.globals[NO_OOM_MEMSIZE] -= actual_val
        return self.state.heap._calloc(sim_nmemb, sim_size)

class OOMrealloc(angr.SimProcedure):
    def run(self, ptr, size):
        self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
                                1: SimTypeLength(self.state.arch) }
        self.return_type = self.ty_ptr(SimTypeTop(size))
        minus = 0
        chunk = self.state.heap.chunk_from_mem(ptr)
        if chunk is not None:
            minus = chunk.get_size()
        actual_val = self.state.heap._conc_alloc_size(size)
        if (actual_val - minus) > self.state.globals[NO_OOM_MEMSIZE]:
            return 0
        self.state.globals[NO_OOM_MEMSIZE] -= (actual_val - minus)
        return self.state.heap._realloc(ptr, size)

class OOMfree(angr.SimProcedure):
    def run(self, ptr):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        chunk = self.state.heap.chunk_from_mem(ptr)
        if chunk is None:
            l.warn('Unknown (double?) free')
            return
        size = chunk.get_size()
        self.state.globals[NO_OOM_MEMSIZE] += size
        return self.state.heap._free(ptr)

class MemLimit(ExplorationTechnique):
    def __init__(self, start_state, heapsize = 1024, claim_trigger=None, claim_amount=512):
        start_state.globals[NO_OOM_MEMSIZE] = heapsize
        start_state.globals[CLAIM_TRIGGERED] = False
        self._trigger = claim_trigger
        self._claim_amount = claim_amount

    def setup(self, simgr):
        simgr._project.hook_symbol('malloc', OOMalloc())
        simgr._project.hook_symbol('calloc', OOMcalloc())
        simgr._project.hook_symbol('realloc', OOMrealloc())
        simgr._project.hook_symbol('free', OOMfree())

    def step(self, simgr, stash='active', **kwargs):
        if self._trigger is None:
            return simgr.step(stash=stash, **kwargs)
        for state in simgr.stashes[stash]:
            if not state.globals[CLAIM_TRIGGERED] and self._trigger(state):
                state.globals[NO_OOM_MEMSIZE] -= self._claim_amount
                state.globals[CLAIM_TRIGGERED] = True
        return simgr.step(stash=stash, **kwargs)
