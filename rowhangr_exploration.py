from angr import ExplorationTechnique
import claripy
import numbers
from copy import deepcopy

import logging
l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)

ROWHAMMER_TRIGGERED = '__rh_triggered'
MAX_MEM_ADDRESSES = 32

class RowHangr(ExplorationTechnique):

    def __init__(self, start_state, no_basicblocks = 0, rh_byte = 0x40050, \
            rh_bit = 0, rh_condition=None, **kwargs):
        self._triggered = False
        self._s = claripy.Solver()
        if isinstance(rh_bit, numbers.Number):
            self._rh_bit = claripy.BVV(rh_bit % 8, 8)
        else:
            self._rh_bit = rh_bit
        if isinstance(rh_byte, numbers.Number):
            self._rh_byte = claripy.BVV(rh_byte, 8*8)
        else:
            self._rh_byte = rh_byte
        self._trigger_cond = rh_condition
        if self._trigger_cond is None:
            if isinstance(no_basicblocks, numbers.Number):
                self._no_bb = claripy.BVV(no_basicblocks, 8*8)
            else:
                self._no_bb = no_basicblocks
            if self._no_bb.length is not None:
                self._nobb_len = claripy.BVV(self._no_bb.length, 8)
            else:
                self._nobb_len = claripy.BVV(8, 8)
        start_state.globals[ROWHAMMER_TRIGGERED] = False
        self._s.add(claripy.ULT(self._rh_bit, 8))
        if 'extra_constraints' in kwargs:
            self._s.add(kwargs['extra_constraints'])


    def _is_unique(self, bv):
        return self._s.min(bv) == self._s.max(bv)


    def setup(self, simgr):
        pass

    def step(self, simgr, stash='active', **kwargs):
        if self._triggered:
            return simgr.step(stash=stash, kwargs)
        if self._trigger_cond is not None:
            for state in list(simgr.stashes[stash]):
                if not state.globals[ROWHAMMER_TRIGGERED] and self._trigger_cond(state):
                    l.debug('Triggering rowhammer on state')
                    rowhammerstates = self._trigger_rowhammer(state)
                    simgr.stashes[stash].extend(rowhammerstates)
                    simgr.stashes[stash].remove(state)
        else:
            if self._s.solution(e=self._no_bb, v=0, exact=True): # claripy.BVV(0,self._nobb_len)):
                self.trigger_rowhammer(simgr, stash=stash, **kwargs)
                self._s.add(self._no_bb != 0) # removing this case for overflow issues
            self._no_bb = self._no_bb - 1
        return simgr.step(stash=stash)

    def trigger_rowhammer(self, simgr, stash='active', **kwargs):
        l.debug('Triggering rowhammer!')
        if self._is_unique(self._no_bb):
            self._triggered = True
        for state in list(simgr.stashes[stash]):
            if not state.globals[ROWHAMMER_TRIGGERED]:
                rowhammers = self._trigger_rowhammer(state)
                simgr.stashes[stash].extend(rowhammers)
                if self._triggered:
                    simgr.stashes[stash].remove(state)
        if self._triggered:
            l.debug('All rowhammer steplocations taken')


    def _trigger_rowhammer(self, state):
        new_states = []
        bits = self._s.eval(self._rh_bit, MAX_MEM_ADDRESSES)#, cast_to=int)
        addresses = self._s.eval(self._rh_byte, MAX_MEM_ADDRESSES/len(bits))#, cast_to=int)
        for addr in addresses:
            for bit in bits:
                l.debug('Next option: 0x{:x} bit no {:d}'.format(addr,bit))
                if not state.mem[addr].uint8_t.resolvable:
                    l.warning('Address not resolvable.')
                    continue
                try:
                    new_state = state.copy() # todo: verify correctness
                    new_byte = new_state.mem[addr].byte.resolved ^ new_state.solver.BVV(1 << bit, 8)
                    l.debug('{} ---> {}'.format(new_state.mem[addr].byte.resolved, new_byte))
                    new_state.mem[addr].byte = new_byte
                    new_state.globals[ROWHAMMER_TRIGGERED] = True
                    new_states.append(new_state)
                except Exception as e:
                    l.warning('Creating rowhammered state failed: {}'.format(e))
        return new_states



    def successors(self, simgr, state, **kwargs):
        if self._triggered:
            return simgr.successors(state, **kwargs)
        return simgr.successors(state, **kwargs)

    def filter(self, simgr, state, **kwargs):
        return simgr.filter(state, **kwargs)

    def complete(self, simgr):
        return False
