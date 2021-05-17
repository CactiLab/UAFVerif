
class Basic_Query:
    def __init__(self,name,head,body):
        self.name = name
        self.head = head
        self.body = body
        self.content = head + body

class Query:
    def __init__(self,scene_name,query_name,content,assumptions):
        self.scene_name = scene_name
        self.query_name = query_name
        self.content = content
        self.assumptions = assumptions