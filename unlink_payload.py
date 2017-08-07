import amd64payload
import i386_payload


class unlink_payload:
    def __init__(self, what, where, offset, length, null=False, bits):
        self.source = what
        self.target = where
        self.offset = offset
        self.length = length
        self.null = null
        if bits == 32:
            self.obj = i386_payload(self.target, self.source, self.offset,
                                    self.length, self.null)
        else:
            self.obj = amd64payload(self.target, self.source, self.offset,
                                    self.length, self.null)
        try:
            self.payload = self.obj.get_payload()
            return self.payload
        except LengthError:
            return None
