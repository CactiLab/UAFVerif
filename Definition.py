
class Query:
    def __init__(self,name,head,content):
        self.name = name
        self.head = head
        self.content = content
        self.query = head + content