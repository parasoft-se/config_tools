from __future__ import annotations

class Fragment:

    def __init__(self, content: str|None, color_code: str):
        self.content = content if content is not None else ''
        self.color_code = color_code

